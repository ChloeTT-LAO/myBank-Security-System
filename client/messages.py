from config.mybank_db import Messages, Users
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
import datetime
from security.encryption import aes_256_gcm_encrypt, aes_256_gcm_decrypt
from security.key_management import retrieve_key_from_db
from security.audit import log_operation

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
key_name = "communication"


def send_message(sender_id: int, receiver_id: int, plain_message: str):
    """
    Send an encrypted message
    """
    session = Session()
    try:
        # Verify sender and receiver exist
        sender = session.query(Users).filter_by(user_id=sender_id).first()
        receiver = session.query(Users).filter_by(user_id=receiver_id).first()

        if not sender or not receiver:
            raise Exception("Sender or receiver not found.")

        # Encrypt message content
        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        message_nonce, encrypted_message = aes_256_gcm_encrypt(plain_message.encode('utf-8'), aes_key)

        # Create message record
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

        # Log operation
        log_operation(
            sender_id,
            "send_message",
            f"Sent encrypted message to user {receiver_id}"
        )

        return message
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def read_message(user_id: int, message_id: int = None):
    """
    Read a single message or all messages
    If message_id is provided, only that message is read
    Otherwise, all messages for the user are retrieved
    """
    session = Session()
    try:
        if message_id:
            # Read a single message
            message = session.query(Messages).filter_by(message_id=message_id).first()

            # Check if the user has permission to read this message
            if not message or (message.sender_id != user_id and message.receiver_id != user_id):
                raise Exception("Message not found or access denied.")

            # Mark as read if the receiver is reading
            if message.receiver_id == user_id and message.read_status == 'unread':
                message.read_status = 'read'
                message.read_at = datetime.datetime.now(tz=datetime.timezone.utc)
                session.commit()

            # Decrypt message content
            plain_message = None
            try:
                if message.ciphertext and message.nonce and message.key_name:
                    aes_key, _ = retrieve_key_from_db(message.key_name)
                    plain_message = aes_256_gcm_decrypt(
                        aes_key,
                        message.nonce,
                        message.ciphertext
                    ).decode('utf-8')
            except Exception as e:
                print(f"Error decrypting message: {str(e)}")

            # Log operation
            log_operation(
                user_id,
                "read_message",
                f"Read message {message_id}"
            )

            return {
                'message_id': message.message_id,
                'sender_id': message.sender_id,
                'receiver_id': message.receiver_id,
                'content': plain_message,
                'sent_at': message.sent_at.isoformat() if message.sent_at else None,
                'read_status': message.read_status,
                'read_at': message.read_at.isoformat() if message.read_at else None
            }
        else:
            # Retrieve all messages for the user (as sender or receiver)
            messages = session.query(Messages).filter(
                (Messages.sender_id == user_id) | (Messages.receiver_id == user_id)
            ).order_by(Messages.sent_at.desc()).all()

            result = []
            for message in messages:
                # Decrypt message content
                plain_message = None
                try:
                    if message.ciphertext and message.nonce and message.key_name:
                        aes_key, _ = retrieve_key_from_db(message.key_name)
                        plain_message = aes_256_gcm_decrypt(
                            aes_key,
                            message.nonce,
                            message.ciphertext
                        ).decode('utf-8')
                except Exception as e:
                    print(f"Error decrypting message: {str(e)}")

                result.append({
                    'message_id': message.message_id,
                    'sender_id': message.sender_id,
                    'receiver_id': message.receiver_id,
                    'content': plain_message,
                    'sent_at': message.sent_at.isoformat() if message.sent_at else None,
                    'read_status': message.read_status,
                    'read_at': message.read_at.isoformat() if message.read_at else None
                })

                # Mark as read if the receiver is reading for the first time
                if message.receiver_id == user_id and message.read_status == 'unread':
                    message.read_status = 'read'
                    message.read_at = datetime.datetime.now(tz=datetime.timezone.utc)

            # Commit all read status updates
            session.commit()

            # Log operation
            log_operation(
                user_id,
                "read_all_messages",
                f"Read all messages ({len(result)} total)"
            )

            return result
    except Exception as e:
        if not message_id:  # Rollback if batch operation fails
            session.rollback()
        raise e
    finally:
        session.close()
