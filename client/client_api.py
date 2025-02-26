import pyotp
from flask import Blueprint, request, jsonify
from functools import wraps
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from authentication import register_user, login, logout, get_session
from config.config import DATABASE_URI
from security.encryption import verify_hmac_sha256
from security.sign_verify import verify_signature
from .loans import apply_for_loan
from .payments import pay_bill, setup_recurring_payment
from .account import update_personal_info, get_account_info, get_transactions
from .messages import send_message, read_message
from config.mybank_db import Users, UserSessions, Accounts

client_bp = Blueprint('client_bp', __name__)
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def client_required(f):
    """
    Decorator: Verify whether the Authorization token in the request is valid and ensure that the current user’s role
    is ‘client’. If the verification is successful, pass the current user object to the decorated route function as
    the first parameter.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        session = Session()

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.replace("Bearer ", "").strip()
        session_obj = get_session(token)
        if not session_obj:
            return jsonify({'error': 'Invalid or expired session'}), 401

        user_id = session_obj.user_id
        user = session.query(Users).filter_by(user_id=user_id).first()
        if user.role.value != 'client':
            return jsonify({'error': 'Client privileges required'}), 403
        return f(user, *args, **kwargs)

    return wrapper


# client register
@client_bp.route('/register', methods=['POST'])
def client_register():
    data = request.json or {}
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    address = data.get('address')
    password = data.get('password')
    public_key = data.get('public_key')

    if not all([name, email, password]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        totp_secret = pyotp.random_base32()

        user_id, hmac_key = register_user(name, email, password, phone, address, public_key, totp_secret, role='client')
        return jsonify({
            'message': 'User registered successfully',
            'user_id': user_id,
            'totp_secret': totp_secret,
            'hmac_key': hmac_key
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# client login
@client_bp.route('/login', methods=['POST'])
def client_login():
    data = request.json or {}
    message = data.get("message", "")
    signature_hex = data.get("signature", "")
    email = data.get('email')
    password = data.get('password')

    is_valid = verify_signature(message, signature_hex)
    if not is_valid:
        return jsonify({"error": "Signature invalid!"}), 400

    user, token = login(email, password)

    if user:
        return jsonify({'message': 'Login successful', 'token': token}), 200
    else:
        return jsonify({'error': token}), 401


# client logout
@client_bp.route('/logout', methods=['POST'])
@client_required
def client_logout(current_client):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    if logout(token):
        return jsonify({'message': 'Logout successful'}), 200
    else:
        return jsonify({'error': 'Logout failed'}), 400


# create account
@client_bp.route('/account/create_account', methods=['POST'])
@client_required
def client_create_account(current_user):
    from .account import create_account

    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    parts = message_str.split("|")
    email = parts[1].split("=")[1]
    account_type = parts[2].split("=")[1]

    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Signature invalid!"}), 400

    try:
        account_number = create_account(current_user.user_id, account_type)
        return jsonify({
            'message': 'User created account successfully',
            'account_number': account_number
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# deposit
@client_bp.route('/transaction/deposit', methods=['POST'])
@client_required
def client_deposit(current_user):
    from .transfer import deposit
    session = Session()

    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    hmac_value = data.get("hmac", "")
    parts = message_str.split("|")
    account_number = parts[2].split("=")[1]
    amount = parts[3].split("=")[1]

    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Signature invalid!"}), 400

    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Signature invalid!"}), 400

    try:
        transaction_id, balance = deposit(account_number, amount)
        return jsonify({
            'transaction_id': transaction_id,
            'balance': balance
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# withdraw
@client_bp.route('/transaction/withdraw', methods=['POST'])
@client_required
def client_withdraw(current_user):
    from .transfer import withdraw
    session = Session()

    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    hmac_value = data.get("hmac", "")
    parts = message_str.split("|")
    account_number = parts[2].split("=")[1]
    amount = parts[3].split("=")[1]

    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Signature invalid!"}), 400

    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Signature invalid!"}), 400

    try:
        transaction_id, balance = withdraw(account_number, amount)
        return jsonify({
            'transaction_id': transaction_id,
            'balance': balance
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# transfer
@client_bp.route('/transaction/transfer', methods=['POST'])
@client_required
def client_transfer(current_user):
    from .transfer import transfer
    session = Session()

    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    hmac_value = data.get("hmac", "")
    parts = message_str.split("|")
    source_account_number = parts[2].split("=")[1]
    destination_account_number = parts[3].split("=")[1]
    amount = parts[4].split("=")[1]

    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Signature invalid!"}), 400

    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Signature invalid!"}), 400

    try:
        transaction_id, balance = transfer(source_account_number, destination_account_number, amount)
        return jsonify({
            'transaction_id': transaction_id,
            'balance': balance
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 与银行代表加密消息通信（发送消息）
@client_bp.route('/message/send', methods=['POST'])
@client_required
def client_send_message(current_user):
    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    hmac_value = data.get("hmac", "")
    parts = message_str.split("|")

    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Signature invalid!"}), 400

    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Signature invalid!"}), 400

    receiver_id = int(parts[2].split("=")[1])
    message_text = parts[3].split("=")[1]
    if not all([receiver_id, message_text]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        message_obj = send_message(current_user.user_id, receiver_id, message_text)
        return jsonify({
            'message': 'Message sent successfully',
            'message_id': message_obj.message_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 查看消息（例如已接收消息）
@client_bp.route('/message/read', methods=['GET'])
@client_required
def client_get_messages(current_client):
    try:
        # 假设 read_message 函数能返回当前用户所有消息
        messages = read_message(current_client.user_id)
        return jsonify({'messages': messages}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 查看账户信息与余额
@client_bp.route('/account/<int:account_id>/info', methods=['GET'])
@client_required
def client_account_info(current_client, account_id):
    try:
        balance = get_account_info(current_client.user_id, account_id)
        return jsonify({
            'account_id': account_id,
            'balance': balance
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 查看交易历史
@client_bp.route('/account/<int:account_id>/transactions', methods=['GET'])
@client_required
def client_transactions(current_client, account_id):
    try:
        tx_list = get_transactions(current_client.user_id, account_id)
        # tx_list 为列表，每项包含交易相关信息（如 transaction_id, amount, timestamp, details 等）
        return jsonify({'transactions': tx_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 支付账单
@client_bp.route('/pay_bill', methods=['POST'])
@client_required
def client_pay_bill(current_client):
    data = request.json or {}
    account_id = data.get('account_id')
    biller_name = data.get('biller_name')
    amount = data.get('amount')
    due_date = data.get('due_date')  # 例如 "2025-03-01"
    if not all([account_id, biller_name, amount, due_date]):
        return jsonify({'error': 'Missing required fields'}), 400
    try:
        bill = pay_bill(current_client.user_id, account_id, biller_name, float(amount), due_date)
        return jsonify({
            'message': 'Bill paid successfully',
            'bill_id': bill.bill_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 设置定期支付
@client_bp.route('/recurring_payment', methods=['POST'])
@client_required
def client_recurring_payment(current_client):
    data = request.json or {}
    account_id = data.get('account_id')
    payment_amount = data.get('payment_amount')
    frequency = data.get('frequency')  # 如 "monthly", "weekly"
    next_payment_date = data.get('next_payment_date')  # 例如 "2025-04-01"
    if not all([account_id, payment_amount, frequency, next_payment_date]):
        return jsonify({'error': 'Missing required fields'}), 400
    try:
        recurring = setup_recurring_payment(current_client.user_id, account_id, float(payment_amount), frequency,
                                            next_payment_date)
        return jsonify({
            'message': 'Recurring payment setup successfully',
            'recurring_payment_id': recurring.recurring_payment_id
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 申请贷款
@client_bp.route('/apply_loan', methods=['POST'])
@client_required
def client_apply_loan(current_client):
    data = request.json or {}
    loan_amount = data.get('loan_amount')
    interest_rate = data.get('interest_rate', 0.0)
    duration = data.get('duration')
    if not all([loan_amount, duration]):
        return jsonify({'error': 'Missing required fields'}), 400
    try:
        loan = apply_for_loan(current_client.user_id, float(loan_amount), float(interest_rate), duration)
        return jsonify({
            'message': 'Loan application submitted',
            'loan_id': loan.loan_id
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 更新个人信息与账户设置
@client_bp.route('/update_profile', methods=['POST'])
@client_required
def client_update_profile(current_client):
    data = request.json or {}
    new_phone = data.get('phone')
    new_address = data.get('address')
    new_name = data.get('name')
    try:
        updated_user = update_personal_info(current_client.user_id, new_phone=new_phone, new_address=new_address,
                                            new_name=new_name)
        return jsonify({
            'message': 'Profile updated successfully',
            'user_id': updated_user.user_id,
            'name': updated_user.name,
            'phone': updated_user.phone,
            'address': updated_user.address
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400



