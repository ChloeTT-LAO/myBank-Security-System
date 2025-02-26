from functools import wraps

import pyotp
from flask import Blueprint, request, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from authentication import get_session, register_user
from config.config import DATABASE_URI
from config.mybank_db import Users
from .security_implement import view_security_logs, perform_system_backup, apply_system_patch
from .key_management import generate_aes_key, rotate_key, generate_rsa_key

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


# @admin_bp.route('/users', methods=['GET'])
# @admin_required
# def api_list_all_users(current_admin):
#     """
#     列出所有用户
#     GET /admin/users
#     """
#     try:
#         users = list_all_users(current_admin)
#         return jsonify({'users': users}), 200
#     except Exception as e:
#         return jsonify({'error': str(e)}), 400
#
# @admin_bp.route('/user/<int:user_id>/role', methods=['POST'])
# @admin_required
# def api_update_user_role(current_admin, user_id):
#     """
#     更新指定用户的角色
#     POST /admin/user/<user_id>/role
#     JSON body: {"new_role": "bank_employee"}
#     """
#     data = request.json or {}
#     new_role = data.get('new_role')
#     if not new_role:
#         return jsonify({'error': 'Missing new_role'}), 400
#
#     try:
#         updated_user = update_user_role(current_admin, user_id, new_role)
#         return jsonify({
#             'message': 'User role updated',
#             'user_id': updated_user.user_id,
#             'new_role': updated_user.role
#         }), 200
#     except Exception as e:
#         return jsonify({'error': str(e)}), 400

@admin_bp.route('/keys/new_rsa', methods=['POST'])
# @admin_required
def api_generate_new_rsa():
    """
    生成新密钥
    POST /admin/keys/new
    JSON body: {"password": "myBank"}
    """
    try:
        generate_rsa_key()
        return jsonify({
            'message': 'Key generated',
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/keys/new_aes', methods=['POST'])
#@admin_required
def api_generate_new_aes():
    """
    生成新密钥
    POST /admin/keys/new
    JSON body: {"key_type": "symmetric", "expiry_days": 30}
    """
    data = request.json or {}
    key_name = data.get('key_name')
    key_type = data.get('key_type')
    expiry_days = data.get('expiry_days')
    key_version = data.get('key_version')

    try:
        key_obj = generate_aes_key(key_name, key_type, key_version, expiry_days)
        return jsonify({
            'message': 'Key generated',
            'key_name': key_obj["key_name"],
            'key_id': key_obj["key_id"],
            'key_version': key_obj["key_version"],
            'key_type': key_obj["key_type"],
            'expiry_date': key_obj["expiry_date"]
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

@admin_bp.route('/security_logs', methods=['GET'])
@admin_required
def api_view_security_logs(current_admin):
    """
    查看安全日志
    GET /admin/security_logs?limit=50
    """
    limit = request.args.get('limit', 50, type=int)
    try:
        logs = view_security_logs(current_admin, limit)
        return jsonify({'security_logs': logs}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/backup', methods=['POST'])
@admin_required
def api_perform_system_backup(current_admin):
    """
    执行系统备份
    POST /admin/backup
    JSON body: {"backup_destination": "/path/to/backup"}
    """
    data = request.json or {}
    backup_destination = data.get('backup_destination', "/default/backup/path")
    try:
        result_msg = perform_system_backup(current_admin, backup_destination)
        return jsonify({'message': result_msg}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/patch', methods=['POST'])
@admin_required
def api_apply_system_patch(current_admin):
    """
    应用系统补丁
    POST /admin/patch
    JSON body: {"patch_info": "Patch v1.2.3"}
    """
    data = request.json or {}
    patch_info = data.get('patch_info', "Unknown patch")
    try:
        result_msg = apply_system_patch(current_admin, patch_info)
        return jsonify({'message': result_msg}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400