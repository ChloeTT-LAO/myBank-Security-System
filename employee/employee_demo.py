import time
import requests

from security.encryption import compute_hmac_sha256
from security.sign_verify import sign_data



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


def employss_send_message(client_id: int, message_text: str, token: str):
    """
    客户端调用此函数向银行职员发送一条安全消息
    :param token: 登录后获得的会话Token
    :param client_email: 当前客户端用户的email, 用于拼接私钥和hmac_key文件名
    :param employee_id: 接收者(银行职员)的 user_id
    :param message_text: 要发送的明文内容
    """

    timestamp = int(time.time())
    # 这里构造需要签名/HMAC的字符串, 例如:
    message_str = f"send_message|email={email}|to={client_id}|content={message_text}|timestamp={timestamp}"

    # 1) 读取客户端私钥 (用于数字签名)
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"employee_secret/{safe_email}_private_key.pem", "rb") as f:
        private_key_pem = f.read()
    signature_bytes = sign_data(message_str.encode('utf-8'), private_key_pem)
    signature_hex = signature_bytes.hex()

    # 2) 读取客户端的 HMAC 密钥 (若要同时用HMAC做完整性)
    with open(f"employee_secret/{safe_email}_hmac_key.txt", "rb") as f:
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
    url = "https://127.0.0.1:5001/employee/messages/send"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print("SendMessage Response:", resp.status_code, resp.text)
    return resp


def employee_read_messages(token: str):
    """
    客户端函数：读取 target_user_id 的全部消息（区分已读/未读）
    """
    timestamp = int(time.time())
    message_str = f"read_message|email={email}|timestamp={timestamp}"

    # 读取本地私钥 & 生成签名
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"employee_secret/{safe_email}_private_key.pem", "rb") as f:
        private_key_pem = f.read()
    signature_bytes = sign_data(message_str.encode('utf-8'), private_key_pem)
    signature_hex = signature_bytes.hex()

    # 读取 HMAC 密钥 & 生成 HMAC
    with open(f"employee_secret/{safe_email}_hmac_key.txt", "rb") as f:
        hmac_key = f.read()
    hmac_value = compute_hmac_sha256(message_str.encode('utf-8'), hmac_key)

    payload = {
        "message": message_str,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = "https://127.0.0.1:5001/client/message/read"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    if resp.status_code == 200:
        # 4) 解析返回的JSON
        data = resp.json()
        unread_list = data.get("unread_messages", [])
        read_list = data.get("read_messages", [])
        print("===== Unread Messages =====")
        for msg in unread_list:
            print(f"Sender: {msg['sender_id']}, "
                  f"Content: {msg['content']}, ")

        print("===== Read Messages =====")
        for msg in read_list:
            print(f"Sender: {msg['sender_id']}, "
                  f"Content: {msg['content']}, ")
    return resp


if __name__ == "__main__":
    print("==================== Welcome to myBank Employee System! ====================")
    print("Please login if you have an account.")

    email = input("Enter your email address: ")
    password = input("Enter your password: ")
    resp = user_login(email, password)
    token = resp.json()["token"]

    while(1):
        print("Please enter the business you want to handle: ")
        print("1. Customer Information 2. Customer Transfer 3. Customer Communication 4. Logout")
        service = input("Enter your service: ")
        if service == "1":
            resp_0 = employee_read_messages(token)
            client_id = int(input("Enter the client's ID: "))
            message = input("Enter your message: ")
            resp = employss_send_message(client_id, message, token)

        elif service == "3":
            resp = user_logout(token)
            break