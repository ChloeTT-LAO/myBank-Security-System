import base64
import datetime
from config.mybank_db import KeyManagement
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, desc
from config.config import DATABASE_URI
from typing import Optional


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
        new_key = KeyManagement(key_name=key_name, key_type=key_type, key_value=base64.b64encode(encrypted_key).decode('utf-8'), key_version=key_version, expiry_date=expiry_date)
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


def retrieve_key_from_db(key_name: str) -> Optional[bytes]:
    """
    从KeyStorage表里拿到加密后的对称密钥，然后用RSA私钥解密
    """
    from .encryption import rsa_decrypt_symmetric_key, load_private_key_from_pem
    session = Session()
    with open("bank_key/private_key.pem", "rb") as private_file:
        private_pem = private_file.read()
    private_key = load_private_key_from_pem(private_pem)
    ks = session.query(KeyManagement).filter_by(key_name=key_name).order_by(desc(KeyManagement.expiry_date)).first()
    if not ks:
        return None
    encrypted_key = base64.b64decode(ks.key_value)
    key_version = ks.key_version
    decrypted_key = rsa_decrypt_symmetric_key(private_key, encrypted_key)
    return decrypted_key, key_version
