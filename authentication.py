import datetime
import time
import uuid
import pyotp
from flask import request, jsonify
from config.mybank_db import Users, UserSessions, SecurityLogs
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
from security.audit import log_operation, log_security_event
from security.behavioral_authentication import update_login_behavior, get_risk_level
from security.encryption import hash_password, check_password, aes_256_gcm_encrypt, generate_hmac_key
from security.key_management import retrieve_key_from_db


engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

# 定义常量
MAX_FAILED_ATTEMPTS = 5  # 最大失败尝试次数
LOCKOUT_DURATION = 15 * 60  # 锁定时间（秒）
SESSION_TIMEOUT = 30 * 60  # 会话超时时间（秒）
IP_TRACKING_ENABLED = True  # 是否启用IP追踪
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
        log_operation(new_user.user_id, "user_registration", f"User {email} registered with role {role}")
        new_user_id = new_user.user_id
        return new_user_id, hmac_key
    except:
        session.rollback()
        raise
    finally:
        session.close()


def login(email: str, password: str, ip_address: str = None, user_agent: str = None):
    session = Session()
    try:
        user = session.query(Users).filter_by(email=email).first()
        if not user:
            # 登录失败但不泄露用户是否存在
            return None, "Invalid email or password"

        current_time = datetime.datetime.now(tz=datetime.timezone.utc)
        if user.account_locked_until and user.account_locked_until > current_time:
            lock_time_remaining = (user.account_locked_until - current_time).total_seconds()
            minutes = int(lock_time_remaining / 60)
            seconds = int(lock_time_remaining % 60)

            # 记录锁定状态下的登录尝试
            log_security_event(
                user.user_id,
                "login_attempt_during_lockout",
                f"Login attempt during account lockout period. Remaining lock time: {minutes}m {seconds}s",
                ip_address,
                user_agent
            )

            return None, f"Account is locked. Please try again in {minutes}m {seconds}s."

        if not check_password(password, user.password_hash):
            # 密码错误，增加失败计数
            user.failed_login_attempts += 1

            # 记录失败的登录尝试
            log_security_event(
                user.user_id,
                "failed_login",
                f"Failed login attempt ({user.failed_login_attempts}/{MAX_FAILED_ATTEMPTS})",
                ip_address,
                user_agent
            )

            # 检查是否达到最大失败尝试次数
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.account_locked_until = current_time + datetime.timedelta(seconds=LOCKOUT_DURATION)
                session.commit()

                # 记录账户锁定事件
                log_security_event(
                    user.user_id,
                    "account_locked",
                    f"Account locked after {MAX_FAILED_ATTEMPTS} failed login attempts",
                    ip_address,
                    user_agent
                )

                return None, f"Account locked due to too many failed attempts. Please try again later."

            session.commit()
            return None, "Invalid email or password"

        # 检查是否需要更改密码
        if user.require_password_change:
            return None, "Password change required. Please reset your password."

        user_totp_secret = user.totp_secret
        totp = pyotp.TOTP(user_totp_secret)
        print("TOTP Code:", totp.now())
        start_time = time.time()

        totp_client = input("Please input the TOTP code: ")
        if time.time() - start_time > 30:
            print("TOTP code expired! Please generate a new one.")
            return jsonify({"error": "TOTP code expired"}), 401

        if not totp.verify(totp_client, valid_window=1):
            # MFA验证失败
            log_security_event(
                user.user_id,
                "failed_mfa",
                "Failed MFA verification during login",
                ip_address,
                user_agent
            )
            return jsonify({"error": "Invalid MFA code"}), 401

        # 重置失败登录计数
        user.failed_login_attempts = 0
        session.commit()

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
        # 记录成功登录
        log_security_event(
            user.user_id,
            "successful_login",
            "User logged in successfully",
            user_agent
        )

        if user and token:
            update_login_behavior(user.user_id, ip_address, user_agent)

            # 根据风险级别决定是否需要额外验证
            risk_level = get_risk_level(user.user_id)
            if risk_level == "high":
                log_security_event(
                    user.user_id,
                    "high_risk_login",
                    "High risk login detected, additional verification may be required",
                    ip_address,
                    user_agent
                )

        # 3) 返回用户对象和 token，供后续调用使用
        return user, token

    finally:
        session.close()


def logout(session_token: str):
    session = Session()
    # try:
    user_session = session.query(UserSessions).filter_by(session_token=session_token).first()
    if user_session and not user_session.logout_time:
        user_session.logout_time = datetime.datetime.now(tz=datetime.timezone.utc)
        # 记录登出操作
        log_operation(
            user_session.user_id,
            "user_logout",
            "User logged out"
        )

        session.commit()
        return True
    return False
    # finally:
    #     session.close()


def get_session(token: str, ip_address: str = None, user_agent: str = None):
    """
    Gets a valid session, returning None if logout_time is not empty or the record does not exist
    """
    session = Session()
    try:
        user_session = session.query(UserSessions) \
            .filter_by(session_token=token) \
            .filter_by(logout_time=None) \
            .first()

        if not user_session:
            return None

        # Check whether the session times out
        current_time = datetime.datetime.now(tz=datetime.timezone.utc)
        time_since_activity = (current_time - user_session.last_activity).total_seconds()

        if time_since_activity > SESSION_TIMEOUT:
            # 会话超时，自动登出
            user_session.logout_time = current_time
            log_security_event(
                user_session.user_id,
                "session_timeout",
                "Session expired due to inactivity",
            )
            session.commit()
            return None

        user_session.last_activity = current_time

        if user_session:
            # 更新行为分析数据
            if ip_address and user_agent:
                update_login_behavior(user_session.user_id, ip_address, user_agent)

            # 检查当前风险级别
            risk_level = get_risk_level(user_session.user_id)

            # 对于高风险会话，可能需要额外的验证
            if risk_level == "high" and not getattr(user_session, 'risk_verified', False):
                log_security_event(
                    user_session.user_id,
                    "high_risk_session",
                    "High risk session activity detected",
                    ip_address,
                    user_agent
                )

            session.commit()
        session.commit()

        return user_session.user_id
    finally:
        session.close()


def is_strong_password(password: str) -> bool:
    """
    检查密码是否足够强壮
    要求：至少8个字符，包含大小写字母、数字和特殊字符
    """
    if len(password) < 8:
        return False

    has_uppercase = False
    has_lowercase = False
    has_digit = False
    has_special = False

    for char in password:
        if char.isupper():
            has_uppercase = True
        elif char.islower():
            has_lowercase = True
        elif char.isdigit():
            has_digit = True
        else:
            has_special = True

    return has_uppercase and has_lowercase and has_digit and has_special


def require_password_change(user_id: int, admin_id: int):
    """
    管理员强制用户在下次登录时更改密码
    """
    session = Session()
    try:
        user = session.query(Users).filter_by(user_id=user_id).first()
        if not user:
            raise Exception("User not found")

        user.require_password_change = True
        session.commit()

        # 记录操作
        log_operation(
            admin_id,
            "require_password_change",
            f"Admin required password change for user_id {user_id}"
        )

        return True
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()
