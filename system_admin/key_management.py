from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI
from security.key_management import generate_encrypted_key, store_key, backup_keys, restore_keys_from_backup, \
    rotate_key, list_all_keys
from security.encryption import generate_rsa_keypair, serialize_private_key_to_pem, serialize_public_key_to_pem


engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

def generate_rsa_key():
    private_key, public_key = generate_rsa_keypair()
    private_pem = serialize_private_key_to_pem(private_key)
    public_pem = serialize_public_key_to_pem(public_key)

    # Save private key to file (write in binary mode)
    with open("bank_key/private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
        private_file.close()

    # Save public key to file
    with open("bank_key/public_key.pem", "wb") as public_file:
        public_file.write(public_pem)
        public_file.close()

    print("🔐 RSA key pair has been generated and saved to files: private_key.pem and public_key.pem")


def generate_aes_key(key_name: str, key_type='symmetric', key_version='v1', expiry_days=30):
    aes_key_encrypt = generate_encrypted_key()
    new_key = store_key(aes_key_encrypt, key_name, key_type, key_version, expiry_days)

    return new_key


def admin_backup_keys(admin_user_id, backup_password, backup_location="key_backups"):
    """Administrator performs key backup"""
    result = backup_keys(admin_user_id, backup_password, backup_location)
    return result


def admin_restore_keys(admin_user_id, backup_file, backup_password):
    """Administrator restores keys from backup"""
    result = restore_keys_from_backup(admin_user_id, backup_file, backup_password)
    return result


def admin_rotate_key(admin_user_id, old_key_id, key_type='symmetric', expiry_days=30):
    """Administrator performs key rotation"""
    result = rotate_key(old_key_id, admin_user_id, key_type, expiry_days)
    return result


def admin_list_keys(admin_user_id, include_expired=False):
    """Administrator views all keys"""
    result = list_all_keys(admin_user_id, include_expired)
    return result