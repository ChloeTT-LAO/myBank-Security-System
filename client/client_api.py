import datetime

import pyotp
from flask import Blueprint, request, jsonify
from functools import wraps
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from authentication import register_user, login, logout, get_session, change_password, reset_totp
from config.config import DATABASE_URI
from security.encryption import verify_hmac_sha256
from security.sign_verify import verify_signature
from security.integrity import verify_high_value_transaction, is_high_risk_transaction
from security.audit import log_operation, get_user_audit_logs
from .account import update_personal_info, get_account_info, get_transactions, create_account
from .messages import send_message, read_message
from .transfer import transfer, deposit, withdraw
from config.mybank_db import Users, UserSessions, Accounts

client_bp = Blueprint('client_bp', __name__)
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def client_required(f):
    """
    装饰器: 验证请求中的Authorization令牌是否有效，并确保当前用户角色为'client'
    如果验证成功，将当前用户对象作为第一个参数传递给装饰的路由函数
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        session = Session()

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.replace("Bearer ", "").strip()

        # 获取客户端IP地址和用户代理
        user_agent = request.headers.get("User-Agent")

        session_obj = get_session(token)
        if not session_obj:
            return jsonify({'error': 'Invalid or expired session'}), 401

        user_id = session_obj.user_id
        user = session.query(Users).filter_by(user_id=user_id).first()
        if user.role.value != 'client':
            # 记录可能的权限越界尝试
            log_operation(user_id, "unauthorized_access_attempt",
                          f"User with role {user.role.value} attempted to access client endpoint", user_agent)
            return jsonify({'error': 'Client privileges required'}), 403

        return f(user, *args, **kwargs)

    return wrapper


# 添加WebAuthn注册API
@client_bp.route('/webauthn/register', methods=['POST'])
@client_required
def api_register_webauthn(current_client):
    """注册WebAuthn凭证"""
    try:
        options = register_webauthn_credential(
            str(current_client.user_id),
            current_client.email
        )

        return jsonify({
            'message': 'WebAuthn registration options generated',
            'options': options
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@client_bp.route('/webauthn/register/verify', methods=['POST'])
@client_required
def api_verify_webauthn_registration(current_client):
    """验证WebAuthn注册"""
    data = request.json or {}
    credential = data.get('credential')

    if not credential:
        return jsonify({'error': 'Credential is required'}), 400

    try:
        result = verify_webauthn_registration(
            str(current_client.user_id),
            credential
        )

        return jsonify({
            'message': 'WebAuthn credential registered successfully',
            'result': result
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@client_bp.route('/webauthn/login', methods=['POST'])
def api_webauthn_login():
    """使用WebAuthn登录"""
    data = request.json or {}
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    try:
        options = authenticate_with_webauthn(username)

        return jsonify({
            'message': 'WebAuthn authentication options generated',
            'options': options
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@client_bp.route('/webauthn/login/verify', methods=['POST'])
def api_verify_webauthn_login():
    """验证WebAuthn登录"""
    data = request.json or {}
    username = data.get('username')
    credential = data.get('credential')

    if not username or not credential:
        return jsonify({'error': 'Username and credential are required'}), 400

    try:
        result = verify_webauthn_authentication(username, credential)

        if result.get('success'):
            # 创建会话
            session = Session()
            user = session.query(Users).filter_by(email=username).first()

            if not user:
                return jsonify({'error': 'User not found'}), 404

            # 生成会话令牌
            import uuid
            token = str(uuid.uuid4())

            # 记录会话
            new_session = UserSessions(
                user_id=user.user_id,
                session_token=token,
                login_time=datetime.datetime.now(tz=datetime.timezone.utc),
                login_method="webauthn"
            )
            session.add(new_session)
            session.commit()

            # 记录成功登录
            log_security_event(
                user.user_id,
                "webauthn_login_success",
                "User logged in using WebAuthn",
                request.remote_addr,
                request.headers.get("User-Agent")
            )

            return jsonify({
                'message': 'Login successful',
                'token': token
            }), 200
        else:
            return jsonify({'error': 'Authentication failed'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 客户注册
@client_bp.route('/register', methods=['POST'])
def client_register():
    data = request.json or {}
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    address = data.get('address')
    password = data.get('password')
    public_key = data.get('public_key')

    # 记录客户端IP和用户代理
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent")

    if not all([name, email, password]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        totp_secret = pyotp.random_base32()

        user_id, hmac_key = register_user(name, email, password, phone, address, public_key, totp_secret, role='client')

        # 记录成功注册
        log_operation(user_id, "user_registration", f"New client registered with email {email}", ip_address, user_agent)

        return jsonify({
            'message': 'User registered successfully',
            'user_id': user_id,
            'totp_secret': totp_secret,
            'hmac_key': hmac_key
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 客户登录
@client_bp.route('/login', methods=['POST'])
def client_login():
    data = request.json or {}
    message = data.get("message", "")
    signature_hex = data.get("signature", "")
    email = data.get('email')
    password = data.get('password')

    # 记录客户端IP和用户代理
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent")

    is_valid = verify_signature(message, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    user, token_or_error = login(email, password, user_agent)

    if user:
        return jsonify({'message': 'Login successful', 'token': token_or_error}), 200
    else:
        return jsonify({'error': token_or_error}), 401


# 客户登出
@client_bp.route('/logout', methods=['POST'])
@client_required
def client_logout(current_client):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()

    if logout(token):
        return jsonify({'message': 'Logout successful'}), 200
    else:
        return jsonify({'error': 'Logout failed'}), 400


# 创建账户
@client_bp.route('/account/create', methods=['POST'])
@client_required
def client_create_account_api(current_user):
    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    hmac_value = data.get("hmac", "")

    parts = message_str.split("|")
    email = parts[1].split("=")[1]
    account_type = parts[2].split("=")[1]

    # 验证数字签名
    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    # 验证消息完整性
    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Message integrity check failed!"}), 400

    try:
        account_number = create_account(current_user.user_id, account_type)

        # 记录操作
        log_operation(current_user.user_id, "account_creation",
                      f"Created new account of type {account_type}")

        return jsonify({
            'message': 'Account created successfully',
            'account_number': account_number
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 存款
@client_bp.route('/transaction/deposit', methods=['POST'])
@client_required
def client_deposit(current_user):
    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    hmac_value = data.get("hmac", "")

    parts = message_str.split("|")
    account_number = parts[2].split("=")[1]
    amount = parts[3].split("=")[1]

    # 验证数字签名
    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    # 验证消息完整性
    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Message integrity check failed!"}), 400

    try:
        transaction_id, balance = deposit(account_number, amount, "Deposit", current_user.user_id,
                                          current_user.hmac_key)

        # 记录操作
        log_operation(current_user.user_id, "deposit",
                      f"Deposited {amount} to account {account_number}")

        return jsonify({
            'transaction_id': transaction_id,
            'balance': balance
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 取款
@client_bp.route('/transaction/withdraw', methods=['POST'])
@client_required
def client_withdraw(current_user):
    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    hmac_value = data.get("hmac", "")

    parts = message_str.split("|")
    account_number = parts[2].split("=")[1]
    amount = parts[3].split("=")[1]

    # 验证数字签名
    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    # 验证消息完整性
    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Message integrity check failed!"}), 400

    try:
        transaction_id, balance = withdraw(account_number, amount, "Withdrawal", current_user.user_id,
                                           current_user.hmac_key)

        # 记录操作
        log_operation(current_user.user_id, "withdrawal",
                      f"Withdrew {amount} from account {account_number}")

        return jsonify({
            'transaction_id': transaction_id,
            'balance': balance
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 转账
@client_bp.route('/transaction/transfer', methods=['POST'])
@client_required
def client_transfer(current_user):
    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    hmac_value = data.get("hmac", "")
    verification_code = data.get("verification_code")

    parts = message_str.split("|")
    source_account_number = parts[2].split("=")[1]
    destination_account_number = parts[3].split("=")[1]
    amount = parts[4].split("=")[1]

    # 验证数字签名
    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    # 验证消息完整性
    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Message integrity check failed!"}), 400

    # 构建交易数据
    transaction_data = {
        "source_account_number": source_account_number,
        "destination_account_number": destination_account_number,
        "amount": amount,
        "transaction_type": "transfer",
        "timestamp": None  # 会在transfer函数中设置
    }

    # 检查是否高风险交易
    if is_high_risk_transaction(transaction_data) and not verification_code:
        return jsonify({
            "error": "Additional verification required for high-value transaction",
            "requires_verification": True
        }), 428  # 428 Precondition Required

    try:
        result = transfer(
            source_account_number,
            destination_account_number,
            amount,
            "Transfer",
            current_user.user_id,
            current_user.hmac_key,
            verification_code
        )

        # 检查是否需要额外验证
        if isinstance(result, dict) and result.get("status") == "additional_verification_required":
            return jsonify(result), 428

        transaction_id, balance = result

        # 记录操作
        log_operation(current_user.user_id, "fund_transfer",
                      f"Transferred {amount} from {source_account_number} to {destination_account_number}")

        return jsonify({
            'transaction_id': transaction_id,
            'balance': balance
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 高值交易验证
@client_bp.route('/transaction/verify', methods=['POST'])
@client_required
def verify_high_value_transaction_api(current_client):
    data = request.json or {}
    transaction_id = data.get('transaction_id')
    verification_code = data.get('verification_code')

    if not transaction_id or not verification_code:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        result = verify_high_value_transaction(transaction_id, current_client.user_id, verification_code)
        if result:
            return jsonify({'message': 'Transaction verified successfully'}), 200
        else:
            return jsonify({'error': 'Verification failed'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 发送加密消息
@client_bp.route('/message/send', methods=['POST'])
@client_required
def client_send_message(current_user):
    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    hmac_value = data.get("hmac", "")

    parts = message_str.split("|")
    receiver_id = int(parts[2].split("=")[1])
    message_text = parts[3].split("=")[1]

    # 验证数字签名
    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    # 验证消息完整性
    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Message integrity check failed!"}), 400

    if not all([receiver_id, message_text]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        message_obj = send_message(current_user.user_id, receiver_id, message_text)

        # 记录操作
        log_operation(current_user.user_id, "message_sent",
                      f"Sent encrypted message to user {receiver_id}")

        return jsonify({
            'message': 'Message sent successfully',
            'message_id': message_obj.message_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 读取消息
@client_bp.route('/message/read', methods=['GET'])
@client_required
def client_get_messages(current_client):
    try:
        messages = read_message(current_client.user_id)

        # 记录操作
        log_operation(current_client.user_id, "message_read",
                      "Retrieved encrypted messages")

        return jsonify({'messages': messages}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 查看账户信息
@client_bp.route('/account/<int:account_id>/info', methods=['GET'])
@client_required
def client_account_info(current_client, account_id):
    try:
        account_info = get_account_info(current_client.user_id, account_id)

        # 记录操作
        log_operation(current_client.user_id, "account_info_access",
                      f"Retrieved information for account {account_id}")

        return jsonify(account_info), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 查看交易历史
@client_bp.route('/account/<int:account_id>/transactions', methods=['GET'])
@client_required
def client_transactions(current_client, account_id):
    try:
        tx_list = get_transactions(current_client.user_id, account_id)

        # 记录操作
        log_operation(current_client.user_id, "transaction_history_access",
                      f"Retrieved transaction history for account {account_id}")

        return jsonify({'transactions': tx_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 安全设置更新
@client_bp.route('/security', methods=['POST'])
@client_required
def update_security_settings(current_client):
    data = request.json or {}
    action = data.get('action')

    if action == 'change_password':
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not current_password or not new_password:
            return jsonify({'error': 'Missing required fields'}), 400

        try:
            result = change_password(current_client.user_id, current_password, new_password)
            return jsonify({'message': 'Password changed successfully'}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    elif action == 'reset_totp':
        try:
            new_totp_secret = reset_totp(current_client.user_id)
            return jsonify({
                'message': 'TOTP reset successfully',
                'totp_secret': new_totp_secret
            }), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    else:
        return jsonify({'error': 'Invalid action'}), 400


# 安全审计日志
@client_bp.route('/audit/logs', methods=['GET'])
@client_required
def get_audit_logs_api(current_client):
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    operation_type = request.args.get('operation_type')

    try:
        logs = get_user_audit_logs(
            current_client.user_id,
            limit=limit,
            offset=offset,
            operation_type=operation_type
        )

        # 记录访问日志操作
        log_operation(current_client.user_id, "audit_log_access",
                      f"Accessed personal audit logs")

        return jsonify({'logs': logs}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 更新个人信息
@client_bp.route('/profile/update', methods=['POST'])
@client_required
def client_update_profile(current_client):
    data = request.json or {}
    new_phone = data.get('phone')
    new_address = data.get('address')

    try:
        updated_user = update_personal_info(current_client.user_id, new_phone=new_phone, new_address=new_address)

        # 记录操作
        log_operation(current_client.user_id, "profile_update",
                      "Updated personal profile information")

        return jsonify({
            'message': 'Profile updated successfully'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400