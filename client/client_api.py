import base64
import datetime

import pyotp
from flask import Blueprint, request, jsonify
from functools import wraps
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from authentication import register_user, login, logout, get_session, is_strong_password
from config.config import DATABASE_URI
from security.encryption import verify_hmac_sha256
from security.sign_verify import verify_signature
from security.integrity import is_high_risk_transaction
from security.audit import log_operation, log_security_event
from security.webauthn import verify_webauthn_registration, authenticate_with_webauthn, register_webauthn_credential, \
    verify_webauthn_authentication
from .account import update_personal_info, get_account_info, get_transactions, create_account
from .messages import send_message, read_message
from .transfer import transfer, deposit, withdraw
from config.mybank_db import Users, UserSessions

client_bp = Blueprint('client_bp', __name__)
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def client_required(f):
    """
    Decorator: verifies that the Authorization token in the request is valid and ensures that the current user role is 'client'
    If the validation is successful, the current user object is passed as the first argument to the decorated routing function
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        session = Session()

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.replace("Bearer ", "").strip()

        # Get the client IP address and user agent
        ip_address = request.headers.get("X-Test-IP", request.remote_addr)
        user_agent = request.headers.get("User-Agent")

        user_id = get_session(token, ip_address, user_agent)
        if not user_id:
            return jsonify({'error': 'Invalid or expired session'}), 401

        user = session.query(Users).filter_by(user_id=user_id).first()
        if user.role.value != 'client':
            # Records possible permission transgression attempts
            log_operation(user_id, "unauthorized_access_attempt",
                          f"User with role {user.role.value} attempted to access client endpoint", user_agent)
            return jsonify({'error': 'Client privileges required'}), 403

        return f(user, *args, **kwargs)

    return wrapper


# Add WebAuthn registration API
@client_bp.route('/webauthn/register', methods=['POST'])
@client_required
def api_register_webauthn(current_client):
    """Register WebAuthn credentials"""
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
    """Verify WebAuthn registration"""
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
    """Log in using WebAuthn"""
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
    """Verify WebAuthn login"""
    data = request.json or {}
    username = data.get('username')
    credential = data.get('credential')

    if not username or not credential:
        return jsonify({'error': 'Username and credential are required'}), 400

    try:
        result = verify_webauthn_authentication(username, credential)

        if result.get('success'):
            session = Session()
            user = session.query(Users).filter_by(email=username).first()

            if not user:
                return jsonify({'error': 'User not found'}), 404

            import uuid
            token = str(uuid.uuid4())

            new_session = UserSessions(
                user_id=user.user_id,
                session_token=token,
                login_time=datetime.datetime.now(tz=datetime.timezone.utc),
            )
            session.add(new_session)
            session.commit()

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

    ip_address = request.headers.get("X-Test-IP", request.remote_addr)
    user_agent = request.headers.get("User-Agent")

    if not all([name, email, password]):
        return jsonify({'error': 'Missing required fields'}), 400

    if not is_strong_password(password):
        password = input('Enter your new password: ')

    try:
        totp_secret = pyotp.random_base32()

        user_id, hmac_key = register_user(name, email, password, phone, address, public_key, totp_secret, role='client')

        log_operation(user_id, "user_registration", f"New client registered with email {email}", ip_address, user_agent)

        return jsonify({
            'message': 'User registered successfully',
            'user_id': user_id,
            'totp_secret': totp_secret,
            'hmac_key': base64.b64encode(hmac_key).decode('utf-8')
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

    ip_address = request.headers.get("X-Test-IP", request.remote_addr)
    user_agent = request.headers.get("User-Agent")

    is_valid = verify_signature(message, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    user, token_or_error = login(email, password, ip_address, user_agent)

    if user:
        return jsonify({'message': 'Login successful', 'token': token_or_error}), 200
    else:
        return jsonify({'error': token_or_error}), 401


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

    # Verify digital signature
    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    # Verify message integrity
    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Message integrity check failed!"}), 400

    try:
        account_number = create_account(current_user.user_id, account_type)

        log_operation(current_user.user_id, "account_creation",
                      f"Created new account of type {account_type}")

        return jsonify({
            'message': 'Account created successfully',
            'account_number': account_number
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# deposit
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

    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Message integrity check failed!"}), 400

    try:
        transaction_id, balance = deposit(account_number, amount, "Deposit", current_user.user_id,
                                          current_user.hmac_key)

        log_operation(current_user.user_id, "deposit",
                      f"Deposited {amount} to account {account_number}")

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
    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    hmac_value = data.get("hmac", "")

    parts = message_str.split("|")
    account_number = parts[2].split("=")[1]
    amount = parts[3].split("=")[1]

    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Message integrity check failed!"}), 400

    try:
        transaction_id, balance = withdraw(account_number, amount, "Withdrawal", current_user.user_id,
                                           current_user.hmac_key)

        log_operation(current_user.user_id, "withdrawal",
                      f"Withdrew {amount} from account {account_number}")

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
    data = request.json or {}
    message_str = data.get("message", "")
    signature_hex = data.get("signature", "")
    hmac_value = data.get("hmac", "")
    verification_code = data.get("verification_code")

    parts = message_str.split("|")
    source_account_number = parts[2].split("=")[1]
    destination_account_number = parts[3].split("=")[1]
    amount = parts[4].split("=")[1]

    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Message integrity check failed!"}), 400

    # Build transaction data
    transaction_data = {
        "source_account_number": source_account_number,
        "destination_account_number": destination_account_number,
        "amount": amount,
        "transaction_type": "transfer",
        "timestamp": None
    }

    # Check for high-risk transactions
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

        # Check if additional validation is required
        if isinstance(result, dict) and result.get("status") == "additional_verification_required":
            return jsonify(result), 428

        transaction_id, balance = result

        log_operation(current_user.user_id, "fund_transfer",
                      f"Transferred {amount} from {source_account_number} to {destination_account_number}")

        return jsonify({
            'transaction_id': transaction_id,
            'balance': balance
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# send message
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

    is_valid = verify_signature(message_str, signature_hex)
    if not is_valid:
        return jsonify({"error": "Digital signature invalid!"}), 400

    is_integrity = verify_hmac_sha256(message_str, current_user, hmac_value)
    if not is_integrity:
        return jsonify({"error": "Message integrity check failed!"}), 400

    if not all([receiver_id, message_text]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        message_obj = send_message(current_user.user_id, receiver_id, message_text)

        log_operation(current_user.user_id, "message_sent",
                      f"Sent encrypted message to user {receiver_id}")

        return jsonify({
            'message': 'Message sent successfully',
            'message_id': message_obj.message_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# read message
@client_bp.route('/message/read', methods=['GET'])
@client_required
def client_get_messages(current_client):
    try:
        messages = read_message(current_client.user_id)

        log_operation(current_client.user_id, "message_read",
                      "Retrieved encrypted messages")

        return jsonify({'messages': messages}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# View Account information
@client_bp.route('/account/<int:account_id>/info', methods=['GET'])
@client_required
def client_account_info(current_client, account_id):
    try:
        account_info = get_account_info(current_client.user_id, account_id)

        log_operation(current_client.user_id, "account_info_access",
                      f"Retrieved information for account {account_id}")

        return jsonify(account_info), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# View transaction history
@client_bp.route('/account/<int:account_id>/transactions', methods=['GET'])
@client_required
def client_transactions(current_client, account_id):
    try:
        tx_list = get_transactions(current_client.user_id, account_id)

        log_operation(current_client.user_id, "transaction_history_access",
                      f"Retrieved transaction history for account {account_id}")

        return jsonify({'transactions': tx_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# Update personal information
@client_bp.route('/profile/update', methods=['POST'])
@client_required
def client_update_profile(current_client):
    data = request.json or {}
    new_phone = data.get('phone')
    new_address = data.get('address')

    try:
        updated_user = update_personal_info(current_client.user_id, new_phone=new_phone, new_address=new_address)

        log_operation(current_client.user_id, "profile_update",
                      "Updated personal profile information")

        return jsonify({
            'message': 'Profile updated successfully'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
