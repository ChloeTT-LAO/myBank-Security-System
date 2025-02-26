import base64
import time
import requests
from security.sign_verify import sign_data
from security.encryption import generate_rsa_keypair, serialize_private_key_to_pem, serialize_public_key_to_pem, \
    compute_hmac_sha256


def user_register(name: str, email: str, password: str, phone: str, address: str):
    # 1. 生成本地RSA密钥对 (演示)
    private_key, public_key = generate_rsa_keypair()
    private_pem = serialize_private_key_to_pem(private_key)
    public_pem = serialize_public_key_to_pem(public_key)

    # 保存私钥到文件（以二进制模式写入）
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"user_secret/{safe_email}_private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
        private_file.close()

    # 4. 构造请求体
    payload = {
        "name": name,
        "address": address,
        "phone": phone,
        "password": password,
        "email": email,
        "public_key": base64.b64encode(public_pem).decode()
    }

    # 5. 向HTTPS服务器发起POST请求
    url = "https://127.0.0.1:5001/client/register"
    # 因为是自签名证书，需要用 verify=False 或指定证书
    resp = requests.post(url, json=payload, verify=False)
    resp_data = resp.json()
    totp_secret = resp_data.get("totp_secret")
    hamc_key = resp_data.get("hamc_key")
    if totp_secret:
        # 把 totp_secret 写入本地文件
        with open(f"user_secret/{safe_email}_totp_secret.txt", "w") as f:
            f.write(totp_secret)
        print("TOTP secret saved to totp_secret.txt")
    else:
        print("No totp_secret found in response.")
    if hamc_key:
        # 把 hamc_key 写入本地文件
        with open(f"user_secret/{safe_email}_hamc_key.txt", "w") as f:
            f.write(hamc_key)
        print("HMAC_key saved to hamc_key.txt")
    print(resp)


def user_login(email: str, password: str):
    timestamp = int(time.time())
    message = f"login|email={email}|timestamp={timestamp}"

    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
        private_pem = private_file.read()
    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()

    payload = {
        "message": message,
        "signature": signature_hex,
        "email": email,
        "password": password
    }

    url = "https://127.0.0.1:5001/client/login"
    resp = requests.post(url, json=payload, verify=False)
    print("Login Response:", resp.status_code, resp.text)
    return resp


def user_logout(token: str):
    url = "https://127.0.0.1:5001/client/logout"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    resp = requests.post(url, headers=headers, json={}, verify=False)
    print("Logout Response:", resp.status_code, resp.text)
    return resp


def user_create_account(email, account_type: str, token: str):
    timestamp = int(time.time())
    message = f"create_account|email={email}|account_type={account_type}|timestamp={timestamp}"

    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
        private_pem = private_file.read()
    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()

    payload = {
        "message": message,
        "signature": signature_hex
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = "https://127.0.0.1:5001/client/account/create_account"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print("Status code:", resp.status_code)
    print("Response:", resp.text)
    return resp


def user_deposit(account_number, amount, token):
    timestamp = int(time.time())
    message = f"create_account|email={email}|account_number={account_number}|amount={amount}|timestamp={timestamp}"

    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
        private_pem = private_file.read()
    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()

    with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as f:
        hmac_key = f.read()
        hmac_value = compute_hmac_sha256(message.encode('utf-8'), hmac_key)

    payload = {
        "message": message,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = "https://127.0.0.1:5001/client/transaction/deposit"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print("Status code:", resp.status_code)
    print("Response:", resp.text)
    return resp


def user_withdraw(account_number, amount, token):
    timestamp = int(time.time())
    message = f"create_account|email={email}|account_number={account_number}|amount={amount}|timestamp={timestamp}"

    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
        private_pem = private_file.read()
    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()

    with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as f:
        hmac_key = f.read()
        hmac_value = compute_hmac_sha256(message.encode('utf-8'), hmac_key)

    payload = {
        "message": message,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = "https://127.0.0.1:5001/client/transaction/withdraw"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print("Status code:", resp.status_code)
    print("Response:", resp.text)
    return resp


def user_transfer(source_account_number, destination_account_number, amount, token):
    timestamp = int(time.time())
    message = f"create_account|email={email}|source_account_number={source_account_number}|destination_account_number={destination_account_number}|amount={amount}|timestamp={timestamp}"

    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
        private_pem = private_file.read()
    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()

    with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as f:
        hmac_key = f.read()
        hmac_value = compute_hmac_sha256(message.encode('utf-8'), hmac_key)

    payload = {
        "message": message,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = "https://127.0.0.1:5001/client/transaction/transfer"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print("Status code:", resp.status_code)
    print("Response:", resp.text)
    return resp


def client_send_message(employee_id: int, message_text: str, token: str):
    """
    客户端调用此函数向银行职员发送一条安全消息
    :param token: 登录后获得的会话Token
    :param client_email: 当前客户端用户的email, 用于拼接私钥和hmac_key文件名
    :param employee_id: 接收者(银行职员)的 user_id
    :param message_text: 要发送的明文内容
    """

    timestamp = int(time.time())
    # 这里构造需要签名/HMAC的字符串, 例如:
    message_str = f"send_message|email={email}|to={employee_id}|content={message_text}|timestamp={timestamp}"

    # 1) 读取客户端私钥 (用于数字签名)
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"user_secret/{safe_email}_private_key.pem", "rb") as f:
        private_key_pem = f.read()
    signature_bytes = sign_data(message_str.encode('utf-8'), private_key_pem)
    signature_hex = signature_bytes.hex()

    # 2) 读取客户端的 HMAC 密钥 (若要同时用HMAC做完整性)
    with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as f:
        hmac_key = f.read()
    hmac_value = compute_hmac_sha256(message_str.encode('utf-8'), hmac_key)

    # 3) 构造请求载荷
    payload = {
        "message": message_str,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    # 4) 携带 Token
    headers = {
        "Authorization": f"Bearer {token}"
    }

    # 5) 发送请求
    url = "https://127.0.0.1:5001/client/messages/send"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print("SendMessage Response:", resp.status_code, resp.text)
    return resp



if __name__ == "__main__":
    print("==================== Welcome to myBank System! ====================")
    print("Please login if you have an account or register an account.")
    user_choice = input("Please enter your choice: 1. Register, 2. Login")
    if user_choice == "1":
        name = input("Enter your name: ")
        email = input("Enter your email address: ")
        password = input("Enter your password: ")
        phone = input("Enter your phone number: ")
        address = input("Enter your address: ")
        user_register(name, email, password, phone, address)

    elif user_choice == "2":
        email = input("Enter your email address: ")
        password = input("Enter your password: ")
        resp = user_login(email, password)
        token = resp.json()["token"]

        while (1):
            print("Please enter the business you want to handle: ")
            print("1.Create account 2.Deposit 3.Withdraw 4.Transfer 5.Contact the customer service 6. Logout")
            service = input("Enter your service: ")
            if service == "1":
                account_type = input("Enter your account type: ")
                resp = user_create_account(email, account_type, token)

            elif service == "2":
                account_number = input("Enter your account number: ")
                amount = input("Enter your amount: ")
                resp = user_deposit(account_number, amount, token)

            elif service == "3":
                account_number = input("Enter your account number: ")
                amount = input("Enter your amount: ")
                resp = user_withdraw(account_number, amount, token)

            elif service == "6":
                resp = user_logout(token)
                break
