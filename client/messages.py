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
    发送加密消息
    """
    session = Session()
    try:
        # 验证发送者和接收者是否存在
        sender = session.query(Users).filter_by(user_id=sender_id).first()
        receiver = session.query(Users).filter_by(user_id=receiver_id).first()

        if not sender or not receiver:
            raise Exception("Sender or receiver not found.")

        # 加密消息内容
        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        message_nonce, encrypted_message = aes_256_gcm_encrypt(plain_message.encode('utf-8'), aes_key)

        # 创建消息记录
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

        # 记录操作
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
    读取一条或所有消息
    如果提供了message_id，则只读取该条消息
    否则读取用户的所有消息
    """
    session = Session()
    try:
        if message_id:
            # 读取单条消息
            message = session.query(Messages).filter_by(message_id=message_id).first()

            # 检查用户是否有权限读取此消息
            if not message or (message.sender_id != user_id and message.receiver_id != user_id):
                raise Exception("Message not found or access denied.")

            # 如果是接收者阅读此消息，标记为已读
            if message.receiver_id == user_id and message.read_status == 'unread':
                message.read_status = 'read'
                message.read_at = datetime.datetime.now(tz=datetime.timezone.utc)
                session.commit()

            # 解密消息内容
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

            # 记录操作
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
            # 读取用户的所有消息（作为发送者或接收者）
            messages = session.query(Messages).filter(
                (Messages.sender_id == user_id) | (Messages.receiver_id == user_id)
            ).order_by(Messages.sent_at.desc()).all()

            result = []
            for message in messages:
                # 解密消息内容
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

                # 如果是接收者首次阅读消息，标记为已读
                if message.receiver_id == user_id and message.read_status == 'unread':
                    message.read_status = 'read'
                    message.read_at = datetime.datetime.now(tz=datetime.timezone.utc)

            # 提交所有已读状态更改
            session.commit()

            # 记录操作
            log_operation(
                user_id,
                "read_all_messages",
                f"Read all messages ({len(result)} total)"
            )

            return result
    except Exception as e:
        if not message_id:  # 如果是批量操作，回滚更改
            session.rollback()
        raise e
    finally:
        session.close()