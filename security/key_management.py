import base64
import datetime
import json
import os

from config.mybank_db import KeyManagement
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, desc
from config.config import DATABASE_URI
from typing import Optional
from security.audit import log_operation

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def generate_encrypted_key():
    from .encryption import generate_aes_256_key, load_public_key_from_pem, rsa_encrypt_symmetric_key
    aes_key = generate_aes_256_key()
    with open("bank_key/public_key.pem", "rb") as public_file:
        public_pem = public_file.read().decode()
    public_key = load_public_key_from_pem(public_pem.encode('utf-8'))
    aes_key_encrypt = rsa_encrypt_symmetric_key(public_key, aes_key)
    return aes_key_encrypt


def store_key(encrypted_key: bytes, key_name, key_type='symmetric', key_version='v1', expiry_days=30):
    session = Session()
    try:
        expiry_date = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=expiry_days)
        new_key = KeyManagement(
            key_name=key_name,
            key_type=key_type,
            key_value=base64.b64encode(encrypted_key).decode('utf-8'),
            key_version=key_version,
            expiry_date=expiry_date
        )
        session.add(new_key)
        session.commit()

        key_dict = {
            "key_name": new_key.key_name,
            "key_id": new_key.key_id,
            "key_type": new_key.key_type,
            "key_version": new_key.key_version,
            "expiry_date": new_key.expiry_date.isoformat()  # 格式化时间戳
        }
        return key_dict  # 返回字典

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def retrieve_key_from_db(key_name: str, key_version: str = None):
    """
    从KeyStorage表里拿到加密后的对称密钥，然后用RSA私钥解密
    """
    from .encryption import rsa_decrypt_symmetric_key, load_private_key_from_pem
    session = Session()
    with open("bank_key/private_key.pem", "rb") as private_file:
        private_pem = private_file.read()
    private_key = load_private_key_from_pem(private_pem)
    ks = session.query(KeyManagement).filter_by(key_name=key_name).order_by(desc(KeyManagement.expiry_date))
    if key_version:
        ks = ks.filter_by(key_version=key_version).first()
    else:
        ks = ks.first()
    if not ks:
        return None
    encrypted_key = base64.b64decode(ks.key_value)
    key_version = ks.key_version
    decrypted_key = rsa_decrypt_symmetric_key(private_key, encrypted_key)
    return decrypted_key, key_version


def rotate_key(old_key_id, admin_user_id, key_type='symmetric', expiry_days=30):
    """
    Key rotation: sets the old key to expire and generates a new key
    """
    session = Session()
    try:
        old_key = session.query(KeyManagement).filter_by(key_id=old_key_id).first()
        if not old_key:
            raise Exception("Old key not found.")

        key_name = old_key.key_name
        old_version = old_key.key_version

        new_version = f"v{int(old_version.replace('v', '')) + 1}"

        old_key.expiry_date = datetime.datetime.now(tz=datetime.timezone.utc)
        session.commit()

        new_key_encrypted = generate_encrypted_key()
        new_key_dict = store_key(
            new_key_encrypted,
            key_name=key_name,
            key_type=key_type,
            key_version=new_version,
            expiry_days=expiry_days
        )

        log_operation(
            admin_user_id,
            "key_rotation",
            f"Rotated key {key_name} from version {old_version} to {new_version}"
        )

        log_operation(
            admin_user_id,
            "key_rotation_reencryption_needed",
            f"Data encrypted with {key_name} version {old_version} needs to be re-encrypted with version {new_version}"
        )

        return new_key_dict

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def backup_keys(admin_user_id, backup_password, backup_location="key_backups"):
    """
    Back up all currently valid keys to a secure location
    The backup file itself is encrypted using the password provided by the administrator
    """
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    session = Session()
    try:
        # Create a backup directory if it does not exist
        if not os.path.exists(backup_location):
            os.makedirs(backup_location)

        # Gets all current valid keys
        current_time = datetime.datetime.now(tz=datetime.timezone.utc)
        valid_keys = session.query(KeyManagement).filter(
            KeyManagement.expiry_date > current_time
        ).all()

        if not valid_keys:
            raise Exception("No valid keys found to backup")

        # Preparing backup data
        backup_data = []
        for key in valid_keys:
            backup_data.append({
                "key_id": key.key_id,
                "key_name": key.key_name,
                "key_type": key.key_type,
                "key_version": key.key_version,
                "key_value": key.key_value,
                "expiry_date": key.expiry_date.isoformat()
            })

        # Derive the encryption key from the password
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        backup_key = base64.urlsafe_b64encode(kdf.derive(backup_password.encode()))

        # Backup data using Fernet symmetric encryption
        fernet = Fernet(backup_key)
        encrypted_data = fernet.encrypt(json.dumps(backup_data).encode())

        # Create a backup File name
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{backup_location}/key_backup_{timestamp}.enc"

        # Write backup files (salt + encrypted data)
        with open(backup_filename, "wb") as f:
            f.write(salt)
            f.write(encrypted_data)

        # Record backup operation
        log_operation(
            admin_user_id,
            "key_backup",
            f"Backed up {len(valid_keys)} keys to {backup_filename}"
        )

        return {
            "message": f"Successfully backed up {len(valid_keys)} keys",
            "backup_file": backup_filename,
            "timestamp": timestamp
        }

    except Exception as e:
        raise e
    finally:
        session.close()


def restore_keys_from_backup(admin_user_id, backup_file, backup_password):
    """
    Recover keys from backup files
    """
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    session = Session()
    try:
        # Reading backup files
        with open(backup_file, "rb") as f:
            file_content = f.read()

        # Extract salt (first 16 bytes) and encrypted data
        salt = file_content[:16]
        encrypted_data = file_content[16:]

        # Derive the decryption key from the password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        backup_key = base64.urlsafe_b64encode(kdf.derive(backup_password.encode()))

        # Decrypt data
        fernet = Fernet(backup_key)
        try:
            decrypted_data = json.loads(fernet.decrypt(encrypted_data).decode())
        except Exception:
            raise Exception("Invalid backup password or corrupted backup file")

        # Restore key to database
        restored_count = 0
        for key_data in decrypted_data:
            # Check whether the key exists
            existing_key = session.query(KeyManagement).filter_by(
                key_name=key_data["key_name"],
                key_version=key_data["key_version"]
            ).first()

            if existing_key:
                continue

            # Create a new key record
            expiry_date = datetime.datetime.fromisoformat(key_data["expiry_date"])
            new_key = KeyManagement(
                key_name=key_data["key_name"],
                key_type=key_data["key_type"],
                key_version=key_data["key_version"],
                key_value=key_data["key_value"],
                expiry_date=expiry_date,
                created_at=datetime.datetime.now(tz=datetime.timezone.utc)
            )
            session.add(new_key)
            restored_count += 1

        session.commit()

        # Record recovery operation
        log_operation(
            admin_user_id,
            "key_restore",
            f"Restored {restored_count} keys from backup {backup_file}"
        )

        return {
            "message": f"Successfully restored {restored_count} keys",
            "backup_file": backup_file
        }

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def list_all_keys(admin_user_id, include_expired=False):
    """
    列出所有密钥（仅供管理员使用）
    """
    session = Session()
    try:
        query = session.query(KeyManagement)

        if not include_expired:
            query = query.filter(
                KeyManagement.expiry_date > datetime.datetime.now(tz=datetime.timezone.utc)
            )

        keys = query.order_by(KeyManagement.key_name, KeyManagement.key_version).all()

        result = []
        for key in keys:
            result.append({
                "key_id": key.key_id,
                "key_name": key.key_name,
                "key_type": key.key_type,
                "key_version": key.key_version,
                "expiry_date": key.expiry_date.isoformat(),
                "created_at": key.created_at.isoformat(),
                "status": "active" if key.expiry_date > datetime.datetime.now(tz=datetime.timezone.utc) else "expired"
            })

        # 记录访问操作
        log_operation(
            admin_user_id,
            "key_list_access",
            f"Listed {len(result)} keys, include_expired={include_expired}"
        )

        return result

    finally:
        session.close()
