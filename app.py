from flask import Flask
from client.client_api import client_bp
from employee.employee_api import employee_bp
from security.sign_verify import verify_data_signature
from system_admin.admin_api import admin_bp
import os

app = Flask(__name__)


# Register each blueprint and set the corresponding URL prefix
app.register_blueprint(client_bp, url_prefix='/client')
app.register_blueprint(employee_bp, url_prefix='/employee')
app.register_blueprint(admin_bp, url_prefix='/admin')


@app.route('/')
def index():
    return "Welcome to MyBank API. Available endpoints: /client, /employee, /admin"


if __name__ == '__main__':
    # Read the certificate and private key path
    cert_path = os.path.join("certificate", "cert.pem")
    key_path = os.path.join("certificate", "key.pem")

    app.run(debug=True, host='0.0.0.0', port=5001, ssl_context=(cert_path, key_path))

