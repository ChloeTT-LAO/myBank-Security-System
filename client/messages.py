from config.mybank_db import Messages
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
import datetime
from security.encryption import aes_256_gcm_encrypt, aes_256_gcm_decrypt
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


def read_message(user_id: int):
    session = Session()
    try:
        unread_msgs = session.query(Messages).filter(
            receiver_id=user_id).filter(read_status='unread').all()

        read_msgs = session.query(Messages).filter(
            receiver_id=user_id).filter(read_status='read').all()

        def msg_to_dict(msg):
            aes_key, key_version = retrieve_key_from_db(key_name=key_name)
            return {
                "sender_id": msg.sender_id,
                "content": aes_256_gcm_decrypt(aes_key, msg.nonce, msg.ciphertext),
                "read_status": msg.read_status
            }

        unread_list = [msg_to_dict(m) for m in unread_msgs]
        read_list = [msg_to_dict(m) for m in read_msgs]

        for msg in unread_msgs:
            msg.read_status = 'read'
        session.commit()

        return {
            "unread_messages": unread_list,
            "read_messages": read_list
        }

    finally:
        session.close()
