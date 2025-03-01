from functools import wraps

import pyotp
from flask import Blueprint, request, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from authentication import get_session, register_user, reset_totp, require_password_change
from config.config import DATABASE_URI
from config.mybank_db import Users
from security.blockchain import get_blockchain_status, verify_transaction_integrity
from .security_implement import view_security_logs, perform_system_backup, apply_system_patch
from .key_management import generate_aes_key, rotate_key, generate_rsa_key, admin_list_keys, admin_backup_keys, \
    admin_restore_keys, admin_rotate_key

admin_bp = Blueprint('admin_bp', __name__)
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def admin_required(f):
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
        if user.role.value != 'system_admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(user, *args, **kwargs)

    return wrapper


# employee creation
@admin_bp.route('/register', methods=['POST'])
# @admin_required
def employee_register():
    data = request.json or {}
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    address = data.get('address')
    password = data.get('password')
    role = data.get('role')
    public_key = data.get('public_key')

    if not all([name, email, password]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        totp_secret = pyotp.random_base32()

        user_id = register_user(name, email, password, phone, address, public_key, totp_secret, role)
        return jsonify({
            'message': f'{role} registered successfully',
            'user_id': user_id,
            'totp_secret': totp_secret
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/keys', methods=['GET'])
@admin_required
def api_list_keys(current_admin):
    """
    获取所有密钥信息（不包含实际密钥值）
    GET /admin/keys?include_expired=false
    """
    include_expired = request.args.get('include_expired', 'false').lower() == 'true'

    try:
        keys = admin_list_keys(current_admin.user_id, include_expired)
        return jsonify({'keys': keys}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/keys/backup', methods=['POST'])
@admin_required
def api_backup_keys(current_admin):
    """
    备份所有有效密钥
    POST /admin/keys/backup
    JSON body: {"backup_password": "your_strong_password", "backup_location": "optional_path"}
    """
    data = request.json or {}
    backup_password = data.get('backup_password')
    backup_location = data.get('backup_location', 'key_backups')

    if not backup_password:
        return jsonify({'error': 'Backup password is required'}), 400

    try:
        result = admin_backup_keys(current_admin.user_id, backup_password, backup_location)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/keys/restore', methods=['POST'])
@admin_required
def api_restore_keys(current_admin):
    """
    从备份恢复密钥
    POST /admin/keys/restore
    JSON body: {"backup_file": "/path/to/backup.enc", "backup_password": "your_strong_password"}
    """
    data = request.json or {}
    backup_file = data.get('backup_file')
    backup_password = data.get('backup_password')

    if not backup_file or not backup_password:
        return jsonify({'error': 'Backup file and password are required'}), 400

    try:
        result = admin_restore_keys(current_admin.user_id, backup_file, backup_password)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/keys/rotate', methods=['POST'])
@admin_required
def api_rotate_key(current_admin):
    """
    轮换指定密钥
    POST /admin/keys/rotate
    JSON body: {"key_id": 123, "key_type": "symmetric", "expiry_days": 30}
    """
    data = request.json or {}
    key_id = data.get('key_id')
    key_type = data.get('key_type', 'symmetric')
    expiry_days = data.get('expiry_days', 30)

    if not key_id:
        return jsonify({'error': 'Key ID is required'}), 400

    try:
        result = admin_rotate_key(current_admin.user_id, key_id, key_type, expiry_days)
        return jsonify({
            'message': 'Key rotated successfully',
            'new_key_data': result
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/keys/new_rsa', methods=['POST'])
@admin_required
def api_generate_new_rsa(current_admin):
    """
    生成新的RSA密钥对
    POST /admin/keys/new_rsa
    """
    try:
        result = generate_rsa_key(current_admin.user_id)
        return jsonify({
            'message': 'RSA key pair generated successfully',
            'details': result
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/keys/new_aes', methods=['POST'])
@admin_required
def api_generate_new_aes(current_admin):
    """
    生成新的AES密钥
    POST /admin/keys/new_aes
    JSON body: {"key_name": "user_info", "key_type": "symmetric", "key_version": "v2", "expiry_days": 30}
    """
    data = request.json or {}
    key_name = data.get('key_name')
    key_type = data.get('key_type', 'symmetric')
    key_version = data.get('key_version', 'v1')
    expiry_days = data.get('expiry_days', 30)

    if not key_name:
        return jsonify({'error': 'Key name is required'}), 400

    try:
        key_data = generate_aes_key(key_name, key_type, key_version, expiry_days, current_admin.user_id)
        return jsonify({
            'message': 'AES key generated successfully',
            'key_data': key_data
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/keys/rotate', methods=['POST'])
@admin_required
def api_rotate_key(current_admin):
    """
    轮换密钥
    POST /admin/keys/rotate
    JSON body: {"old_key_id": 1, "key_type": "symmetric", "expiry_days": 30}
    """
    data = request.json or {}
    old_key_id = data.get('old_key_id')
    key_type = data.get('key_type', 'symmetric')
    expiry_days = data.get('expiry_days', 30)

    if old_key_id is None:
        return jsonify({'error': 'Missing old_key_id'}), 400

    try:
        new_key_obj = rotate_key(old_key_id, key_type, expiry_days)
        return jsonify({
            'message': 'Key rotated successfully',
            'new_key_id': new_key_obj.key_id,
            'new_key_type': new_key_obj.key_type,
            'new_key_expiry_date': new_key_obj.expiry_date.isoformat()
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/security/logs', methods=['GET'])
@admin_required
def get_security_logs_api(current_admin):
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    event_type = request.args.get('event_type')
    user_id = request.args.get('user_id', type=int)

    try:
        logs = get_security_logs(
            current_admin.user_id,
            limit=limit,
            offset=offset,
            event_type=event_type,
            user_id=user_id
        )
        return jsonify({'logs': logs}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/user/<int:user_id>/security', methods=['POST'])
@admin_required
def admin_manage_user_security(current_admin, user_id):
    data = request.json or {}
    action = data.get('action')

    if action == 'reset_totp':
        try:
            new_totp_secret = reset_totp(user_id, current_admin.user_id)
            return jsonify({
                'message': 'User TOTP reset successfully',
                'user_id': user_id,
                'totp_secret': new_totp_secret
            }), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    elif action == 'require_password_change':
        try:
            result = require_password_change(user_id, current_admin.user_id)
            return jsonify({
                'message': 'User will be required to change password on next login',
                'user_id': user_id
            }), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    else:
        return jsonify({'error': 'Invalid action'}), 400


@admin_bp.route('/blockchain/status', methods=['GET'])
@admin_required
def api_blockchain_status(current_admin):
    """获取区块链状态"""
    try:
        status = get_blockchain_status()

        return jsonify({
            'message': 'Blockchain status retrieved',
            'status': status
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/blockchain/verify/<int:transaction_id>', methods=['GET'])
@admin_required
def api_verify_blockchain_transaction(current_admin, transaction_id):
    """验证区块链交易"""
    try:
        result = verify_transaction_integrity(transaction_id, current_admin.user_id)

        return jsonify({
            'message': 'Transaction verification completed',
            'result': result
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
