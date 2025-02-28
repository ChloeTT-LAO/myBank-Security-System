import pyotp
from flask import Blueprint, request, jsonify
from sqlalchemy import create_engine
from authentication import get_session, login, logout
from client.messages import send_message, read_message
from config.mybank_db import Users, SecurityLogs
from security.encryption import verify_hmac_sha256
from security.sign_verify import verify_signature
from security.audit import log_operation, log_security_event
from .access import view_customer_accounts, view_customer_transactions
from .transaction_process import deposit_to_customer, withdraw_from_customer, employee_transfer
from .information_update import employee_update_customer_info
from .monitor import mark_suspicious_transaction, freeze_customer_account
from functools import wraps
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI

employee_bp = Blueprint('employee_bp', __name__)
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def employee_required(f):
    """
    装饰器: 验证请求中的Authorization令牌是否有效，并确保当前用户角色为'bank_employee'
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
        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent")

        session_obj = get_session(token, ip_address)
        if not session_obj:
            return jsonify({'error': 'Invalid or expired session'}), 401

        user_id = session_obj.user_id
        user = session.query(Users).filter_by(user_id=user_id).first()
        if user.role.value != 'bank_employee':
            # 记录可能的权限越界尝试
            log_operation(user_id, "unauthorized_access_attempt",
                          f"User with role {user.role.value} attempted to access employee endpoint",
                          ip_address, user_agent)
            return jsonify({'error': 'Employee privileges required'}), 403

        return f(user, *args, **kwargs)

    return wrapper


# 员工登录 (使用通用的登录端点)

# 员工向客户发送加密消息
@employee_bp.route('/message/send', methods=['POST'])
@employee_required
def employee_send_message(current_employee):
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
    is_integrity = verify_hmac_sha256(message_str, current_employee, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Message integrity check failed!"}), 400

    if not all([receiver_id, message_text]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        # 检查接收者是否存在且是客户
        session = Session()
        receiver = session.query(Users).filter_by(user_id=receiver_id).first()

        if not receiver:
            return jsonify({'error': 'Receiver not found'}), 404

        if receiver.role.value != 'client':
            return jsonify({'error': 'Receiver must be a client'}), 400

        message_obj = send_message(current_employee.user_id, receiver_id, message_text)

        # 记录操作
        log_operation(current_employee.user_id, "message_sent",
                      f"Employee sent encrypted message to client {receiver_id}")

        return jsonify({
            'message': 'Message sent successfully',
            'message_id': message_obj.message_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 员工查看消息
@employee_bp.route('/message/read', methods=['GET'])
@employee_required
def employee_get_messages(current_employee):
    try:
        messages = read_message(current_employee.user_id)

        # 记录操作
        log_operation(current_employee.user_id, "message_read",
                      "Employee retrieved encrypted messages")

        return jsonify({'messages': messages}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 查看客户账户
@employee_bp.route('/customer/<int:customer_id>/accounts', methods=['GET'])
@employee_required
def api_view_customer_accounts(current_employee, customer_id):
    """
    查看指定客户的所有账户
    """
    try:
        result = view_customer_accounts(current_employee, customer_id)

        # 记录操作
        log_operation(current_employee.user_id, "customer_accounts_access",
                      f"Employee viewed accounts for customer {customer_id}")

        return jsonify({'accounts': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 查看客户交易记录
@employee_bp.route('/account/<int:account_id>/transactions', methods=['GET'])
@employee_required
def api_view_account_transactions(current_employee, account_id):
    """
    查看指定账户的交易记录
    """
    try:
        result = view_customer_transactions(current_employee, account_id)

        # 记录操作
        log_operation(current_employee.user_id, "account_transactions_access",
                      f"Employee viewed transactions for account {account_id}")

        return jsonify({'transactions': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 员工代客户存款
@employee_bp.route('/deposit', methods=['POST'])
@employee_required
def api_deposit_to_customer(current_employee):
    data = request.json or {}
    account_id = data.get('account_id')
    amount = data.get('amount', 0.0)
    note = data.get('note', "Deposit")

    if not account_id or not amount:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        tx = deposit_to_customer(current_employee, account_id, float(amount), note)

        # 记录操作
        log_operation(current_employee.user_id, "employee_deposit",
                      f"Employee deposited {amount} to account {account_id}")

        return jsonify({
            'message': 'Deposit successful',
            'transaction_id': tx.transaction_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 员工代客户取款
@employee_bp.route('/withdraw', methods=['POST'])
@employee_required
def api_withdraw_from_customer(current_employee):
    data = request.json or {}
    account_id = data.get('account_id')
    amount = data.get('amount', 0.0)
    note = data.get('note', "Withdrawal")

    if not account_id or not amount:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        tx = withdraw_from_customer(current_employee, account_id, float(amount), note)

        # 记录操作
        log_operation(current_employee.user_id, "employee_withdrawal",
                      f"Employee withdrew {amount} from account {account_id}")

        return jsonify({
            'message': 'Withdrawal successful',
            'transaction_id': tx.transaction_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 员工代客户转账
@employee_bp.route('/transfer', methods=['POST'])
@employee_required
def api_employee_transfer(current_employee):
    data = request.json or {}
    source_account_id = data.get('source_account_id')
    destination_account_id = data.get('destination_account_id')
    amount = data.get('amount', 0.0)
    note = data.get('note', "Employee Transfer")

    if not source_account_id or not destination_account_id or not amount:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        tx = employee_transfer(current_employee, source_account_id, destination_account_id, float(amount), note)

        # 记录操作
        log_operation(current_employee.user_id, "employee_transfer",
                      f"Employee transferred {amount} from account {source_account_id} to account {destination_account_id}")

        return jsonify({
            'message': 'Transfer successful',
            'transaction_id': tx.transaction_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 更新客户信息
@employee_bp.route('/customer/<int:customer_id>/update', methods=['POST'])
@employee_required
def api_update_customer_info(current_employee, customer_id):
    data = request.json or {}
    phone = data.get('phone')
    address = data.get('address')

    try:
        updated_customer = employee_update_customer_info(
            current_employee,
            customer_id,
            new_phone=phone,
            new_address=address
        )

        # 记录操作
        log_operation(current_employee.user_id, "customer_info_update",
                      f"Employee updated information for customer {customer_id}")

        return jsonify({
            'message': 'Customer information updated successfully',
            'customer_id': customer_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 标记可疑交易
@employee_bp.route('/transaction/<int:transaction_id>/mark_suspicious', methods=['POST'])
@employee_required
def api_mark_suspicious_transaction(current_employee, transaction_id):
    data = request.json or {}
    reason = data.get('reason', "Suspicious activity detected")

    try:
        tx = mark_suspicious_transaction(current_employee, transaction_id, reason)

        # 记录操作
        log_operation(current_employee.user_id, "mark_suspicious_transaction",
                      f"Employee marked transaction {transaction_id} as suspicious: {reason}")

        # 记录安全事件
        log_security_event(
            current_employee.user_id,
            "suspicious_transaction_marked",
            f"Transaction {transaction_id} marked as suspicious: {reason}"
        )

        return jsonify({
            'message': 'Transaction marked as suspicious',
            'transaction_id': transaction_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 冻结客户账户
@employee_bp.route('/account/<int:account_id>/freeze', methods=['POST'])
@employee_required
def api_freeze_customer_account(current_employee, account_id):
    data = request.json or {}
    reason = data.get('reason', "Security concern")

    try:
        account = freeze_customer_account(current_employee, account_id, reason)

        # 记录操作
        log_operation(current_employee.user_id, "freeze_account",
                      f"Employee froze account {account_id}: {reason}")

        # 记录安全事件
        log_security_event(
            current_employee.user_id,
            "account_frozen",
            f"Account {account_id} frozen: {reason}"
        )

        return jsonify({
            'message': 'Account frozen successfully',
            'account_id': account_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 查找客户
@employee_bp.route('/customer/search', methods=['GET'])
@employee_required
def api_search_customer(current_employee):
    email = request.args.get('email')

    if not email:
        return jsonify({'error': 'Email parameter is required'}), 400

    session = Session()
    try:
        customer = session.query(Users).filter_by(email=email, role='client').first()

        if not customer:
            return jsonify({'error': 'Customer not found'}), 404

        # 记录操作
        log_operation(current_employee.user_id, "customer_search",
                      f"Employee searched for customer with email {email}")

        return jsonify({
            'customer_id': customer.user_id,
            'email': customer.email,
            'role': customer.role.value
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    finally:
        session.close()