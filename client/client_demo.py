import base64
import hashlib
import json
import time
import uuid

import requests
import getpass
import pyotp
import os
from security.sign_verify import sign_data
from security.encryption import generate_rsa_keypair, serialize_private_key_to_pem, serialize_public_key_to_pem, \
    compute_hmac_sha256


def ensure_directory(directory):
    """Ensure directory existence"""
    if not os.path.exists(directory):
        os.makedirs(directory)


def user_register(name: str, email: str, password: str, phone: str, address: str, ip_address: str = None,
                  user_agent: str = None):
    """Register a new user"""
    print("\n=== Register a new user ===")

    # 确保存储目录存在
    ensure_directory("user_secret")

    # 1. 生成本地RSA密钥对
    print("Generate an RSA key pair...")
    private_key, public_key = generate_rsa_keypair()
    private_pem = serialize_private_key_to_pem(private_key)
    public_pem = serialize_public_key_to_pem(public_key)

    # 保存私钥到文件
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"user_secret/{safe_email}_private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
        private_file.close()
    print(f"The private key is saved to user_secret/{safe_email}_private_key.pem")

    # 2. 构造请求体
    payload = {
        "name": name,
        "address": address,
        "phone": phone,
        "password": password,
        "email": email,
        "public_key": base64.b64encode(public_pem).decode()
    }

    headers = {}
    if ip_address:
        headers["X-Test-IP"] = ip_address
    if user_agent:
        headers["User-Agent"] = user_agent

    # 3. 发送注册请求
    print("Send a registration request...")
    url = "https://127.0.0.1:5001/client/register"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 201:
        resp_data = resp.json()
        totp_secret = resp_data.get("totp_secret")
        hmac_key = resp_data.get("hmac_key")

        # 保存TOTP密钥
        if totp_secret:
            with open(f"user_secret/{safe_email}_totp_secret.txt", "w") as f:
                f.write(totp_secret)
            print(f"TOTP key is saved to user_secret/{safe_email}_totp_secret.txt")

            # 显示TOTP二维码URL
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=email, issuer_name="MyBank")
            print(f"TOTP URI: {totp_uri}")
            print("Use Google Authenticator or another TOTP application to scan this URI to set up two-factor authentication")

        # 保存HMAC密钥
        if hmac_key:
            with open(f"user_secret/{safe_email}_hmac_key.txt", "wb") as f:
                f.write(base64.b64decode(hmac_key))
            print(f"HMAC key is saved to user_secret/{safe_email}_hmac_key.txt")

        print("Registered successfully! Please keep your key file safe and do not disclose it to others.")
    else:
        print(f"Fail to register: {resp.text}")


def user_login(email: str, password: str, ip_address: str = None,
                  user_agent: str = None):
    """user login"""
    print("\n=== Login ===")

    # 1. Construct signature message
    timestamp = int(time.time())
    message = f"login|email={email}|timestamp={timestamp}"

    # 2. Read the private key file and sign it
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()
    except FileNotFoundError:
        print(f"Error: Private key file not found: user_secret/{safe_email}_private_key.pem")
        return None

    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()

    # 3. Construct request body
    payload = {
        "message": message,
        "signature": signature_hex,
        "email": email,
        "password": password
    }

    headers = {}
    if ip_address:
        headers["X-Test-IP"] = ip_address
    if user_agent:
        headers["User-Agent"] = user_agent

    # 4. Send login request
    print("Sending login request...")
    url = "https://127.0.0.1:5001/client/login"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        print("Login successful！")
        return resp
    else:
        print(f"Fail to login: {resp.text}")
        return None


def user_logout(token: str):
    """用户登出"""
    print("\n=== 用户登出 ===")

    url = "https://127.0.0.1:5001/client/logout"
    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送登出请求...")
    resp = requests.post(url, headers=headers, json={}, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        print("登出成功！")
        return True
    else:
        print(f"登出失败: {resp.text}")
        return False


def user_create_account(email: str, account_type: str, token: str, ip_address: str = None,
                  user_agent: str = None):
    """ create a new account """
    print("\n=== create a new account ===")

    # 1. 构造签名消息
    timestamp = int(time.time())
    message = f"create_account|email={email}|account_type={account_type}|timestamp={timestamp}"

    # 2. 读取私钥和HMAC密钥
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()

        with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as hmac_file:
            hmac_key = hmac_file.read()
    except FileNotFoundError as e:
        print(f"Error: Key file not found - {str(e)}")
        return None

    # 3. 生成签名和HMAC
    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()
    hmac_value = compute_hmac_sha256(message.encode('utf-8'), base64.b64decode(hmac_key))

    # 4. 构造请求体
    payload = {
        "message": message,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    headers = {}
    if ip_address:
        headers["X-Test-IP"] = ip_address
    if user_agent:
        headers["User-Agent"] = user_agent
    headers["Authorization"] = f"Bearer {token}"


    print("Send an account creation request...")
    url = "https://127.0.0.1:5001/client/account/create"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"Server respond: {resp.status_code}")

    if resp.status_code == 201:
        data = resp.json()
        account_number = data.get("account_number")
        print(f"Account created successfully! Account number: {account_number}")
        return account_number
    else:
        print(f"Account creation failure: {resp.text}")
        return None


def user_deposit(email: str, account_number: str, amount: str, token: str):
    """存款操作"""
    print(f"\n=== 存款 {amount} 到账户 {account_number} ===")

    # 1. 构造签名消息
    timestamp = int(time.time())
    message = f"deposit|email={email}|account_number={account_number}|amount={amount}|timestamp={timestamp}"

    # 2. 读取私钥和HMAC密钥
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()

        with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as hmac_file:
            hmac_key = hmac_file.read()
    except FileNotFoundError as e:
        print(f"错误: 找不到密钥文件 - {str(e)}")
        return None

    # 3. 生成签名和HMAC
    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()
    hmac_value = compute_hmac_sha256(message.encode('utf-8'), hmac_key)

    # 4. 构造请求体
    payload = {
        "message": message,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    # 5. 发送请求
    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送存款请求...")
    url = "https://127.0.0.1:5001/client/transaction/deposit"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        transaction_id = data.get("transaction_id")
        balance = data.get("balance")
        print(f"存款成功! 交易ID: {transaction_id}")
        print(f"当前余额: {balance}")
        return transaction_id, balance
    else:
        print(f"存款失败: {resp.text}")
        return None, None


def user_withdraw(email: str, account_number: str, amount: str, token: str):
    """取款操作"""
    print(f"\n=== 从账户 {account_number} 取款 {amount} ===")

    # 1. 构造签名消息
    timestamp = int(time.time())
    message = f"withdraw|email={email}|account_number={account_number}|amount={amount}|timestamp={timestamp}"

    # 2. 读取私钥和HMAC密钥
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()

        with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as hmac_file:
            hmac_key = hmac_file.read()
    except FileNotFoundError as e:
        print(f"错误: 找不到密钥文件 - {str(e)}")
        return None

    # 3. 生成签名和HMAC
    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()
    hmac_value = compute_hmac_sha256(message.encode('utf-8'), hmac_key)

    # 4. 构造请求体
    payload = {
        "message": message,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    # 5. 发送请求
    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送取款请求...")
    url = "https://127.0.0.1:5001/client/transaction/withdraw"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        transaction_id = data.get("transaction_id")
        balance = data.get("balance")
        print(f"取款成功! 交易ID: {transaction_id}")
        print(f"当前余额: {balance}")
        return transaction_id, balance
    else:
        print(f"取款失败: {resp.text}")
        return None, None


def user_transfer(email: str, source_account_number: str, destination_account_number: str, amount: str, token: str):
    """转账操作"""
    print(f"\n=== 从账户 {source_account_number} 转账 {amount} 到账户 {destination_account_number} ===")

    # 1. 构造签名消息
    timestamp = int(time.time())
    message = f"transfer|email={email}|source_account_number={source_account_number}|destination_account_number={destination_account_number}|amount={amount}|timestamp={timestamp}"

    # 2. 读取私钥和HMAC密钥
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()

        with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as hmac_file:
            hmac_key = hmac_file.read()

        with open(f"user_secret/{safe_email}_totp_secret.txt", "r") as totp_file:
            totp_secret = totp_file.read().strip()
    except FileNotFoundError as e:
        print(f"错误: 找不到密钥文件 - {str(e)}")
        return None

    # 3. 生成签名和HMAC
    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()
    hmac_value = compute_hmac_sha256(message.encode('utf-8'), hmac_key)

    # 4. 构造请求体
    payload = {
        "message": message,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    # 5. 发送请求
    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送转账请求...")
    url = "https://127.0.0.1:5001/client/transaction/transfer"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    # 检查是否需要额外验证（高风险交易）
    if resp.status_code == 428:  # 请求需要额外验证
        print("高风险交易，需要额外验证...")

        # 生成当前TOTP码
        totp = pyotp.TOTP(totp_secret)
        current_totp = totp.now()
        print(f"当前TOTP码: {current_totp}")

        verification_code = input("请输入您的身份验证器应用中的验证码: ")

        # 添加验证码并重新请求
        payload["verification_code"] = verification_code
        resp = requests.post(url, json=payload, headers=headers, verify=False)
        print(f"验证后服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        transaction_id = data.get("transaction_id")
        balance = data.get("balance")
        print(f"转账成功! 交易ID: {transaction_id}")
        print(f"当前余额: {balance}")
        return transaction_id, balance
    else:
        print(f"转账失败: {resp.text}")
        return None, None


def client_send_message(email: str, employee_id: int, message_text: str, token: str):
    """向银行职员发送加密消息"""
    print(f"\n=== 向员工 {employee_id} 发送加密消息 ===")

    # 1. 构造签名消息
    timestamp = int(time.time())
    message_str = f"send_message|email={email}|to={employee_id}|content={message_text}|timestamp={timestamp}"

    # 2. 读取私钥和HMAC密钥
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()

        with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as hmac_file:
            hmac_key = hmac_file.read()
    except FileNotFoundError as e:
        print(f"错误: 找不到密钥文件 - {str(e)}")
        return None

    # 3. 生成签名和HMAC
    signature_bytes = sign_data(message_str.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()
    hmac_value = compute_hmac_sha256(message_str.encode('utf-8'), hmac_key)

    # 4. 构造请求体
    payload = {
        "message": message_str,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    # 5. 发送请求
    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送加密消息...")
    url = "https://127.0.0.1:5001/client/message/send"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        message_id = data.get("message_id")
        print(f"消息发送成功! 消息ID: {message_id}")
        return message_id
    else:
        print(f"消息发送失败: {resp.text}")
        return None


def get_account_info(token: str, account_id: int):
    """获取账户信息"""
    print(f"\n=== 获取账户 {account_id} 信息 ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送请求...")
    url = f"https://127.0.0.1:5001/client/account/{account_id}/info"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        info = resp.json()
        print("账户信息:")
        for key, value in info.items():
            print(f"  {key}: {value}")
        return info
    else:
        print(f"获取账户信息失败: {resp.text}")
        return None


def get_transaction_history(token: str, account_id: int):
    """获取交易历史"""
    print(f"\n=== 获取账户 {account_id} 交易历史 ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送请求...")
    url = f"https://127.0.0.1:5001/client/account/{account_id}/transactions"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        transactions = resp.json().get("transactions", [])
        print(f"找到 {len(transactions)} 条交易记录:")
        for idx, tx in enumerate(transactions, 1):
            print(f"\n交易 #{idx}:")
            for key, value in tx.items():
                print(f"  {key}: {value}")
        return transactions
    else:
        print(f"获取交易历史失败: {resp.text}")
        return None


def change_password(token: str, current_password: str, new_password: str):
    """更改密码"""
    print("\n=== 更改密码 ===")

    payload = {
        "action": "change_password",
        "current_password": current_password,
        "new_password": new_password
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送密码更改请求...")
    url = "https://127.0.0.1:5001/client/security"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        print("密码更改成功!")
        return True
    else:
        print(f"密码更改失败: {resp.text}")
        return False


def update_profile(token: str, phone: str = None, address: str = None):
    """更新个人资料"""
    print("\n=== 更新个人资料 ===")

    payload = {}
    if phone:
        payload["phone"] = phone
    if address:
        payload["address"] = address

    if not payload:
        print("错误: 至少需要提供一个要更新的字段")
        return False

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送个人资料更新请求...")
    url = "https://127.0.0.1:5001/client/profile/update"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        print("个人资料更新成功!")
        return True
    else:
        print(f"个人资料更新失败: {resp.text}")
        return False


def register_webauthn(email, token):
    """注册WebAuthn凭证"""
    print("\n=== 注册WebAuthn凭证 ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = "https://127.0.0.1:5001/client/webauthn/register"
    resp = requests.post(url, headers=headers, json={}, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        options = resp.json().get("options")

        print("请在浏览器中完成WebAuthn注册...")
        print("注册选项:", json.dumps(options, indent=2))

        # 模拟浏览器返回的凭证
        # 在实际情况下，这应该由浏览器的WebAuthn API生成
        credential = {
            "id": "simulated-credential-id-" + str(uuid.uuid4()),
            "rawId": base64.b64encode(os.urandom(32)).decode('ascii'),
            "type": "public-key",
            "response": {
                "clientDataJSON": {
                    "type": "webauthn.create",
                    "challenge": options["challenge"],
                    "origin": "https://127.0.0.1:5001"
                },
                "attestationObject": {
                    "fmt": "none",
                    "authData": {
                        "rpIdHash": hashlib.sha256(b"bankingsystem.example.com").digest(),
                        "flags": 0x41,  # AT and UP flags
                        "counter": 1,
                        "attestedCredentialData": {
                            "aaguid": os.urandom(16),
                            "credentialId": base64.b64encode(os.urandom(32)).decode('ascii'),
                            "credentialPublicKey": base64.b64encode(os.urandom(65)).decode('ascii')
                        }
                    }
                }
            }
        }

        # 验证注册
        verify_url = "https://127.0.0.1:5001/client/webauthn/register/verify"
        verify_resp = requests.post(
            verify_url,
            headers=headers,
            json={"credential": credential},
            verify=False
        )
        print(f"验证响应: {verify_resp.status_code}")
        print(verify_resp.json())

        return verify_resp.json()
    else:
        print(f"注册失败: {resp.text}")
        return None


def webauthn_login(email):
    """使用WebAuthn登录"""
    print("\n=== WebAuthn登录 ===")

    url = "https://127.0.0.1:5001/client/webauthn/login"
    resp = requests.post(url, json={"username": email}, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        options = resp.json().get("options")

        print("请在浏览器中完成WebAuthn验证...")
        print("验证选项:", json.dumps(options, indent=2))

        # 模拟浏览器返回的凭证
        # 在实际情况下，这应该由浏览器的WebAuthn API生成
        credential = {
            "id": options["allowCredentials"][0]["id"],
            "rawId": base64.b64encode(os.urandom(32)).decode('ascii'),
            "type": "public-key",
            "response": {
                "clientDataJSON": {
                    "type": "webauthn.get",
                    "challenge": options["challenge"],
                    "origin": "https://127.0.0.1:5001"
                },
                "authenticatorData": base64.b64encode(os.urandom(37)).decode('ascii'),
                "signature": base64.b64encode(os.urandom(64)).decode('ascii'),
                "userHandle": base64.b64encode(os.urandom(32)).decode('ascii')
            }
        }

        # 验证登录
        verify_url = "https://127.0.0.1:5001/client/webauthn/login/verify"
        verify_resp = requests.post(
            verify_url,
            json={
                "username": email,
                "credential": credential
            },
            verify=False
        )
        print(f"验证响应: {verify_resp.status_code}")

        if verify_resp.status_code == 200:
            token = verify_resp.json().get("token")
            print("登录成功!")
            return token
        else:
            print(f"登录失败: {verify_resp.text}")
            return None
    else:
        print(f"登录请求失败: {resp.text}")
        return None


def test_risk_behavior(email, token):
    """测试用户行为风险评估"""
    print("\n=== 测试行为风险评估 ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    # 1. 进行几次正常交易建立基线
    print("进行几次正常交易以建立基线...")

    # 创建账户
    account_type = "checking"
    resp = user_create_account(email, account_type, token)
    if resp.status_code != 201:
        print("创建账户失败")
        return

    account_number = resp.json().get("account_number")

    # 存款
    amount = "1000"
    resp = user_deposit(email, account_number, amount, token)
    if resp.status_code != 200:
        print("存款失败")
        return

    # 查询余额多次，建立正常行为模式
    for _ in range(3):
        url = f"https://127.0.0.1:5001/client/account/1/info"
        requests.get(url, headers=headers, verify=False)
        time.sleep(1)

    print("基线建立完成")

    # 2. 测试异常行为 - 大额转账
    print("\n测试异常行为 - 大额转账...")

    # 创建第二个账户
    resp = user_create_account(email, "savings", token)
    if resp.status_code != 201:
        print("创建第二个账户失败")
        return

    second_account = resp.json().get("account_number")

    # 尝试大额转账（应该触发额外验证）
    large_amount = "900"
    resp = user_transfer(email, account_number, second_account, large_amount, token)

    print(f"转账响应: {resp.status_code}")
    print(resp.json())

    if resp.status_code == 428:  # 需要额外验证
        print("系统正确识别了高风险交易并要求额外验证!")
    else:
        print("未触发额外验证，可能是风险评估阈值未达到")

    return resp.json()


def view_audit_logs(token):
    """查看审计日志"""
    print("\n=== 查看审计日志 ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = "https://127.0.0.1:5001/client/audit/logs"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        logs = resp.json().get("logs", [])
        print(f"找到 {len(logs)} 条审计记录:")
        for idx, log in enumerate(logs[:5], 1):  # 只显示前5条
            print(f"\n日志 #{idx}:")
            print(f"  操作: {log.get('operation')}")
            print(f"  详情: {log.get('details')}")
            print(f"  时间: {log.get('log_time')}")
        return logs
    else:
        print(f"获取审计日志失败: {resp.text}")
        return None


if __name__ == "__main__":
    print("==================== Welcome to the MyBank client ====================")

    while True:
        print("\nselecting operation:")
        print("1. Register")
        print("2. Login")
        print("0. Logout")

        main_choice = input("Please enter options: ")

        if main_choice == "1":
            # Register
            name = input("Please enter name: ")
            email = input("Please enter email address: ")
            password = getpass.getpass("Please enter password: ")
            phone = input("Please enter phone number: ")
            address = input("Please enter address: ")

            user_register(name, email, password, phone, address)

        elif main_choice == "2":
            email = None
            token = None
            print("Please select a login method:")
            print("1. Password login")
            print("2. WebAuthn login")
            login_choice = input("Please enter options: ")

            if login_choice == "1":
                email = input("Please enter your email address: ")
                password = getpass.getpass("Please enter your password: ")
                resp = user_login(email, password)
                if resp.status_code == 200:
                    token = resp.json()["token"]

            elif login_choice == "2":
                email = input("Please enter your email address: ")
                token = webauthn_login(email)

            if token:
                # The login succeeds, and the function menu is displayed
                while True:
                    print("\n--- User function menu ---")
                    print("1. Create a new account")
                    print("2. Deposit")
                    print("3. Withdraw")
                    print("4. Transfer")
                    print("5. View Account information")
                    print("6. View transaction history")
                    print("7. Send encrypted messages to bank staff")
                    print("8. Security settings")
                    print("9. Update profile")
                    print("10. Register WebAuthn credentials")
                    print("11. Test behavioral risk assessment")
                    print("0. Logout")

                    sub_choice = input("Please enter options: ")

                    if sub_choice == "1":
                        account_type = input("Please enter the account type (savings/checking): ")
                        account_number = user_create_account(email, account_type, token)

                    elif sub_choice == "2":
                        account_number = input("请输入账号: ")
                        amount = input("请输入金额: ")
                        user_deposit(email, account_number, amount, token)

                    elif sub_choice == "3":
                        account_number = input("请输入账号: ")
                        amount = input("请输入金额: ")
                        user_withdraw(email, account_number, amount, token)

                    elif sub_choice == "4":
                        source_account = input("请输入源账号: ")
                        destination_account = input("请输入目标账号: ")
                        amount = input("请输入金额: ")
                        user_transfer(email, source_account, destination_account, amount, token)

                    elif sub_choice == "5":
                        account_id = int(input("请输入账户ID: "))
                        get_account_info(token, account_id)

                    elif sub_choice == "6":
                        account_id = int(input("请输入账户ID: "))
                        get_transaction_history(token, account_id)

                    elif sub_choice == "7":
                        employee_id = int(input("请输入银行职员ID: "))
                        message = input("请输入消息内容: ")
                        client_send_message(email, employee_id, message, token)

                    elif sub_choice == "8":
                        # 安全设置
                        print("\n安全设置:")
                        print("1. 更改密码")
                        print("2. 重置TOTP")
                        print("0. 返回")

                        security_choice = input("请输入选项: ")

                        if security_choice == "1":
                            current_password = getpass.getpass("请输入当前密码: ")
                            new_password = getpass.getpass("请输入新密码: ")
                            confirm_password = getpass.getpass("请确认新密码: ")

                            if new_password != confirm_password:
                                print("错误: 两次输入的新密码不匹配")
                            else:
                                change_password(token, current_password, new_password)

                    elif sub_choice == "9":
                        # 更新个人资料
                        update_phone = input("请输入新电话号码 (留空保持不变): ")
                        update_address = input("请输入新地址 (留空保持不变): ")

                        phone = update_phone if update_phone else None
                        address = update_address if update_address else None

                        update_profile(token, phone, address)

                    elif sub_choice == "10":
                        # 注册WebAuthn凭证
                        register_webauthn(email, token)

                    elif sub_choice == "11":
                        # 测试行为风险评估
                        test_risk_behavior(email, token)

                    elif sub_choice == "0":
                        # 登出
                        if user_logout(token):
                            break
                    else:
                        print("无效选项，请重试")

        elif main_choice == "0":
            print("感谢使用MyBank客户端，再见!")
            break

        else:
            print("无效选项，请重试")