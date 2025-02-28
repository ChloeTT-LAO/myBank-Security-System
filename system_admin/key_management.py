from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI
from security.key_management import generate_encrypted_key, store_key, backup_keys, restore_keys_from_backup, \
    rotate_key, list_all_keys
from security.encryption import generate_rsa_keypair, serialize_private_key_to_pem, serialize_public_key_to_pem, rsa_encrypt_symmetric_key, load_public_key_from_pem, generate_aes_256_key
import datetime
from config.mybank_db import KeyManagement

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

def generate_rsa_key(admin_id):
    private_key, public_key = generate_rsa_keypair()
    private_pem = serialize_private_key_to_pem(private_key)
    public_pem = serialize_public_key_to_pem(public_key)

    # 保存私钥到文件（以二进制模式写入）
    with open("bank_key/private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
        private_file.close()

    # 保存公钥到文件
    with open("bank_key/public_key.pem", "wb") as public_file:
        public_file.write(public_pem)
        public_file.close()

    print("🔐 RSA 密钥对已生成并保存到文件：private_key.pem 和 public_key.pem")


def generate_aes_key(key_name: str, admin_id, key_type='symmetric', key_version='v1', expiry_days=30):
    aes_key_encrypt = generate_encrypted_key()
    new_key = store_key(aes_key_encrypt, key_name, key_type, key_version, expiry_days)

    return new_key


def admin_backup_keys(admin_user_id, backup_password, backup_location="key_backups"):
    """管理员执行密钥备份"""
    result = backup_keys(admin_user_id, backup_password, backup_location)
    return result


def admin_restore_keys(admin_user_id, backup_file, backup_password):
    """管理员从备份恢复密钥"""
    result = restore_keys_from_backup(admin_user_id, backup_file, backup_password)
    return result


def admin_rotate_key(admin_user_id, old_key_id, key_type='symmetric', expiry_days=30):
    """管理员执行密钥轮换"""
    result = rotate_key(old_key_id, admin_user_id, key_type, expiry_days)
    return result


def admin_list_keys(admin_user_id, include_expired=False):
    """管理员查看所有密钥"""
    result = list_all_keys(admin_user_id, include_expired)
    return result