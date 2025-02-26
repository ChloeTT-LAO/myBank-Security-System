import base64

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI
from config.mybank_db import Users
from .encryption import load_private_key_from_pem, load_public_key_from_pem

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def sign_data(message: bytes, private_key_pem: bytes) -> bytes:
    """
    使用私钥对消息进行签名，返回签名（二进制）
    """
    private_key = load_private_key_from_pem(private_key_pem)
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_data_signature(message: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    使用公钥验证签名
    """
    public_key = load_public_key_from_pem(public_key_pem)
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True

    except Exception:
        return False


def verify_signature(message_str, signature_hex):
    session = Session()

    parts = message_str.split("|")
    email = parts[1].split("=")[1]
    ks = session.query(Users).filter_by(email=email)
    public_key_pem = base64.b64decode(ks.first().public_key)

    from_bytes = bytes.fromhex(signature_hex)
    is_valid = verify_data_signature(message_str.encode('utf-8'), from_bytes, public_key_pem)
    return is_valid
