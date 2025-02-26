from config.mybank_db import Messages
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
import datetime
from security.encryption import aes_256_gcm_encrypt
from security.key_management import retrieve_key_from_db

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
key_name = "communication"


def send_message(sender_id: int, receiver_id: int, plain_message: str):
    session = Session()
    try:
        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        message_nonce, encrypted_message = aes_256_gcm_encrypt(plain_message.encode('utf-8'), aes_key)
        message = Messages(
            sender_id=sender_id,
            receiver_id=receiver_id,
            nonce=message_nonce,
            ciphertext=encrypted_message,
            sent_at=datetime.datetime.now(tz=datetime.timezone.utc),
            read_status='unread',
            key_version=key_version,
            key_name=key_name
        )
        session.add(message)
        session.commit()
        return message
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def read_message(message_id: int):
    session = Session()
    try:
        message = session.query(Messages).filter_by(message_id=message_id).first()
        if message:
            # 解密消息内容
            plain_message = decrypt_data(message.message_body)
            return plain_message
        else:
            return None
    finally:
        session.close()