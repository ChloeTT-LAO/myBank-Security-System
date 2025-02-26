import datetime
import uuid
import pyotp
from flask import request, jsonify
from config.mybank_db import Users, UserSessions
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
from security.encryption import hash_password, check_password, aes_256_gcm_encrypt, generate_hmac_key
from security.key_management import retrieve_key_from_db


engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


key_name = "user_info"

def register_user(name: str, email: str, password: str, phone: str, address: str, public_key: str, totp_secret: str, role: str = 'client'):
    session = Session()
    try:
        existing_user = session.query(Users).filter_by(email=email).first()
        if existing_user:
            raise Exception("User already exists.")

        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        name_nonce, encrypted_name = aes_256_gcm_encrypt(name.encode('utf-8'), aes_key)
        phone_nonce, encrypted_phone = aes_256_gcm_encrypt(phone.encode('utf-8'), aes_key)
        address_nonce, encrypted_address = aes_256_gcm_encrypt(address.encode('utf-8'), aes_key)

        hmac_key = generate_hmac_key()


        new_user = Users(
            email=email,
            password_hash=hash_password(password),
            role=role,
            public_key=public_key,
            encrypted_name=encrypted_name,
            name_nonce=name_nonce,
            encrypted_phone=encrypted_phone,
            phone_nonce=phone_nonce,
            encrypted_address=encrypted_address,
            address_nonce=address_nonce,
            key_name="user_info",
            totp_secret=totp_secret,
            key_version=key_version,
            hmac_key=hmac_key
        )
        session.add(new_user)
        session.commit()
        new_user_id = new_user.user_id
        return new_user_id, hmac_key
    except:
        session.rollback()
        raise
    finally:
        session.close()


def login(email: str, password: str):
    session = Session()
    try:
        user = session.query(Users).filter_by(email=email).first()
        if user and check_password(password, user.password_hash):
            user_totp_secret = user.totp_secret
            totp = pyotp.TOTP(user_totp_secret)
            print("TOTP Code:", totp.now())
            totp_client = input("Please input the TOTP code: ")
            if not totp.verify(totp_client, valid_window=1):
                return jsonify({"error": "Invalid MFA code"}), 401

            # 1) 生成随机 session token（使用 uuid）
            token = str(uuid.uuid4())

            # 2) 在 UserSessions 表中创建新的会话记录
            new_session = UserSessions(
                user_id=user.user_id,
                session_token=token,
                login_time=datetime.datetime.now(tz=datetime.timezone.utc)
            )
            session.add(new_session)
            session.commit()

            # 3) 返回用户对象和 token，供后续调用使用
            return user, token
        else:
            # 用户不存在或密码错误
            return None, None
    finally:
        session.close()

def logout(session_token: str):
    session = Session()
    # try:
    user_session = session.query(UserSessions).filter_by(session_token=session_token).first()
    if user_session and not user_session.logout_time:
        user_session.logout_time = datetime.datetime.now(tz=datetime.timezone.utc)
        session.commit()
        return True
    return False
    # finally:
    #     session.close()

def get_session(token: str):
    """
    获取有效的会话，如果 logout_time 不为空或记录不存在则返回 None
    """
    session = Session()
    try:
        user_session = session.query(UserSessions)\
                              .filter_by(session_token=token)\
                              .filter_by(logout_time=None)\
                              .first()
        return user_session
    finally:
        session.close()