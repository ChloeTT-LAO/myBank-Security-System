import pyotp
from flask import Blueprint, request, jsonify
from sqlalchemy import create_engine
from authentication import get_session
from client.messages import send_message
from config.mybank_db import Users
from security.encryption import verify_hmac_sha256
from security.sign_verify import verify_signature
from .access import view_customer_accounts, view_customer_transactions
from .transaction_process import deposit_to_customer, withdraw_from_customer, employee_transfer
from functools import wraps
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI
from .information_update import employee_update_customer_info
from .monitor import mark_suspicious_transaction, freeze_customer_account

employee_bp = Blueprint('employee_bp', __name__)
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def employee_required(f):
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
        if user.role.value != 'employee':
            return jsonify({'error': 'Employee privileges required'}), 403
        return f(user, *args, **kwargs)

    return wrapper


@employee_bp.route('/message/send', methods=['POST'])
@employee_required
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


@employee_bp.route('/customer/<int:customer_id>/accounts', methods=['GET'])
@employee_required
def api_view_customer_accounts(current_employee):
    """
    Only bank_employee is allowed to access.
    The current_employee parameter comes from the decorator.
    """
    try:
        result = view_customer_accounts(current_employee, customer_id)
        return jsonify({'accounts': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@employee_bp.route('/deposit', methods=['POST'])
@employee_required
def api_deposit_to_customer(current_employee):
    data = request.json
    account_id = data.get('account_id')
    amount = data.get('amount', 0.0)
    note = data.get('note', "Deposit")

    try:
        tx = deposit_to_customer(current_employee, account_id, amount, note)
        return jsonify({
            'message': 'Deposit successful',
            'transaction_id': tx.transaction_id
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400