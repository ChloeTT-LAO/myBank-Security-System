from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI
from security.key_management import generate_encrypted_key, store_key
from security.encryption import generate_rsa_keypair, serialize_private_key_to_pem, serialize_public_key_to_pem, rsa_encrypt_symmetric_key, load_public_key_from_pem, generate_aes_256_key
import datetime
from config.mybank_db import KeyManagement

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

def generate_rsa_key():
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


def generate_aes_key(key_name: str, key_type='symmetric', key_version='v1', expiry_days=30):
    aes_key_encrypt = generate_encrypted_key()
    new_key = store_key(aes_key_encrypt, key_name, key_type, key_version, expiry_days)

    return new_key


def rotate_key(old_key_id, key_type='symmetric', expiry_days=30):
    """
    轮换密钥：将旧密钥设为过期，新生成一把新的密钥
    """
    session = Session()
    try:
        # 标记旧密钥为过期
        old_key = session.query(KeyManagement).filter_by(key_id=old_key_id).first()
        if not old_key:
            raise Exception("Old key not found.")
        old_key.expiry_date = datetime.datetime.now(tz=datetime.timezone.utc)  # 立即过期
        session.commit()
    finally:
        session.close()

    # 生成新密钥
    return generate_new_key(key_type, expiry_days)