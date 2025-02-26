from functools import wraps
from flask import request, jsonify
from authentication import get_session


def employee_required(f):
    """
    仅允许 role='bank_employee' 的用户访问此路由
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        session_obj = get_session(token)
        if not session_obj:
            return jsonify({'error': 'Invalid or expired session'}), 401

        user = session_obj.user  # 假设 session_obj.user 包含 role
        if user.role != 'bank_employee':
            return jsonify({'error': 'Forbidden: not an employee'}), 403

        # 若角色匹配，则继续执行原函数
        return f(user, *args, **kwargs)

    return decorated_function