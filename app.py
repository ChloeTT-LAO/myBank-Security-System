from flask import Flask, request, jsonify
from client.client_api import client_bp
from employee.employee_api import employee_bp
from security.sign_verify import verify_data_signature
from system_admin.admin_api import admin_bp
import os

app = Flask(__name__)

# 加载配置（可选，如果你在 config.py 中有Flask相关的配置）
# app.config.from_pyfile('config.py')

# 注册各个蓝图，设置对应的 URL 前缀
app.register_blueprint(client_bp, url_prefix='/client')
app.register_blueprint(employee_bp, url_prefix='/employee')
app.register_blueprint(admin_bp, url_prefix='/admin')

@app.route('/')
def index():
    return "Welcome to MyBank API. Available endpoints: /client, /employee, /admin"





if __name__ == '__main__':
    # 读取证书和私钥路径
    cert_path = os.path.join("certificate", "cert.pem")
    key_path = os.path.join("certificate", "key.pem")

    # 在开发环境下启用调试模式，监听所有网络接口
    app.run(debug=True, host='0.0.0.0', port=5001, ssl_context=(cert_path, key_path))