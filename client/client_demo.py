import base64
import time
import requests
import getpass
import pyotp
import os
from security.sign_verify import sign_data
from security.encryption import generate_rsa_keypair, serialize_private_key_to_pem, serialize_public_key_to_pem, \
    compute_hmac_sha256


def ensure_directory(directory):
    """确保目录存在"""
    if not os.path.exists(directory):
        os.makedirs(directory)


def user_register(name: str, email: str, password: str, phone: str, address: str):
    """注册新用户"""
    print("\n=== 注册新用户 ===")

    # 确保存储目录存在
    ensure_directory("user_secret")

    # 1. 生成本地RSA密钥对
    print("生成RSA密钥对...")
    private_key, public_key = generate_rsa_keypair()
    private_pem = serialize_private_key_to_pem(private_key)
    public_pem = serialize_public_key_to_pem(public_key)

    # 保存私钥到文件
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"user_secret/{safe_email}_private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
        private_file.close()
    print(f"私钥已保存到 user_secret/{safe_email}_private_key.pem")

    # 2. 构造请求体
    payload = {
        "name": name,
        "address": address,
        "phone": phone,
        "password": password,
        "email": email,
        "public_key": base64.b64encode(public_pem).decode()
    }

    # 3. 发送注册请求
    print("发送注册请求...")
    url = "https://127.0.0.1:5001/client/register"
    resp = requests.post(url, json=payload, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 201:
        resp_data = resp.json()
        totp_secret = resp_data.get("totp_secret")
        hmac_key = resp_data.get("hmac_key")

        # 保存TOTP密钥
        if totp_secret:
            with open(f"user_secret/{safe_email}_totp_secret.txt", "w") as f:
                f.write(totp_secret)
            print(f"TOTP密钥已保存到 user_secret/{safe_email}_totp_secret.txt")

            # 显示TOTP二维码URL
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=email, issuer_name="MyBank")
            print(f"TOTP URI: {totp_uri}")
            print("请使用Google Authenticator或其他TOTP应用扫描此URI以设置双因素认证")

        # 保存HMAC密钥
        if hmac_key:
            with open(f"user_secret/{safe_email}_hmac_key.txt", "w") as f:
                f.write(hmac_key)
            print(f"HMAC密钥已保存到 user_secret/{safe_email}_hmac_key.txt")

        print("注册成功！请妥善保管您的密钥文件，不要透露给他人。")
    else:
        print(f"注册失败: {resp.text}")


def user_login(email: str, password: str):
    """用户登录"""
    print("\n=== 用户登录 ===")

    # 1. 构造签名消息
    timestamp = int(time.time())
    message = f"login|email={email}|timestamp={timestamp}"

    # 2. 读取私钥文件并签名
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()
    except FileNotFoundError:
        print(f"错误: 找不到私钥文件 user_secret/{safe_email}_private_key.pem")
        return None

    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()

    # 3. 构造请求体
    payload = {
        "message": message,
        "signature": signature_hex,
        "email": email,
        "password": password
    }

    # 4. 发送登录请求
    print("发送登录请求...")
    url = "https://127.0.0.1:5001/client/login"
    resp = requests.post(url, json=payload, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        token = resp.json().get("token")
        print("登录成功！")
        return token
    else:
        print(f"登录失败: {resp.text}")
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


def user_create_account(email: str, account_type: str, token: str):
    """创建新账户"""
    print("\n=== 创建新账户 ===")

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

    print("发送创建账户请求...")
    url = "https://127.0.0.1:5001/client/account/create"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 201:
        data = resp.json()
        account_number = data.get("account_number")
        print(f"账户创建成功! 账号: {account_number}")
        return account_number
    else:
        print(f"创建账户失败: {resp.text}")
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


def reset_totp(token: str, email: str):
    """重置TOTP"""
    print("\n=== 重置TOTP ===")

    payload = {
        "action": "reset_totp"
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送TOTP重置请求...")
    url = "https://127.0.0.1:5001/client/security"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        new_totp_secret = data.get("totp_secret")

        # 保存新的TOTP密钥
        safe_email = email.replace("@", "_at_").replace(".", "_dot_")
        with open(f"user_secret/{safe_email}_totp_secret.txt", "w") as f:
            f.write(new_totp_secret)

        # 显示TOTP二维码URL
        totp_uri = pyotp.totp.TOTP(new_totp_secret).provisioning_uri(
            name=email, issuer_name="MyBank")

        print("TOTP重置成功!")
        print(f"新的TOTP密钥已保存到 user_secret/{safe_email}_totp_secret.txt")
        print(f"TOTP URI: {totp_uri}")
        print("请使用Google Authenticator或其他TOTP应用扫描此URI以更新您的双因素认证")

        return True
    else:
        print(f"TOTP重置失败: {resp.text}")
        return False


def get_audit_logs(token: str):
    """获取审计日志"""
    print("\n=== 获取审计日志 ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送请求...")
    url = "https://127.0.0.1:5001/client/audit/logs"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        logs = resp.json().get("logs", [])
        print(f"找到 {len(logs)} 条审计日志记录:")
        for idx, log in enumerate(logs, 1):
            print(f"\n日志 #{idx}:")
            print(f"  操作: {log.get('operation')}")
            print(f"  详情: {log.get('details')}")
            print(f"  时间: {log.get('log_time')}")
        return logs
    else:
        print(f"获取审计日志失败: {resp.text}")
        return None


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


if __name__ == "__main__":
    print("==================== 欢迎使用MyBank客户端 ====================")

    while True:
        print("\n选择操作:")
        print("1. 注册新账户")
        print("2. 登录")
        print("0. 退出")

        main_choice = input("请输入选项: ")

        if main_choice == "1":
            # 注册新账户
            name = input("请输入姓名: ")
            email = input("请输入电子邮箱: ")
            password = getpass.getpass("请输入密码: ")
            phone = input("请输入电话号码: ")
            address = input("请输入地址: ")

            user_register(name, email, password, phone, address)

        elif main_choice == "2":
            # 登录
            email = input("请输入电子邮箱: ")
            password = getpass.getpass("请输入密码: ")

            token = user_login(email, password)

            if token:
                # 登录成功，显示功能菜单
                while True:
                    print("\n--- 用户功能菜单 ---")
                    print("1. 创建新账户")
                    print("2. 存款")
                    print("3. 取款")
                    print("4. 转账")
                    print("5. 查看账户信息")
                    print("6. 查看交易历史")
                    print("7. 发送加密消息给银行职员")
                    print("8. 安全设置")
                    print("9. 查看审计日志")
                    print("10. 更新个人资料")
                    print("0. 登出")

                    sub_choice = input("请输入选项: ")

                    if sub_choice == "1":
                        # 创建新账户
                        account_type = input("请输入账户类型 (savings/checking): ")
                        user_create_account(email, account_type, token)

                    elif sub_choice == "2":
                        # 存款
                        account_number = input("请输入账号: ")
                        amount = input("请输入金额: ")
                        user_deposit(email, account_number, amount, token)

                    elif sub_choice == "3":
                        # 取款
                        account_number = input("请输入账号: ")
                        amount = input("请输入金额: ")
                        user_withdraw(email, account_number, amount, token)

                    elif sub_choice == "4":
                        # 转账
                        source_account = input("请输入源账号: ")
                        destination_account = input("请输入目标账号: ")
                        amount = input("请输入金额: ")
                        user_transfer(email, source_account, destination_account, amount, token)

                    elif sub_choice == "5":
                        # 查看账户信息
                        account_id = int(input("请输入账户ID: "))
                        get_account_info(token, account_id)

                    elif sub_choice == "6":
                        # 查看交易历史
                        account_id = int(input("请输入账户ID: "))
                        get_transaction_history(token, account_id)

                    elif sub_choice == "7":
                        # 发送加密消息
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

                        elif security_choice == "2":
                            reset_totp(token, email)

                    elif sub_choice == "9":
                        # 查看审计日志
                        get_audit_logs(token)

                    elif sub_choice == "10":
                        # 更新个人资料
                        update_phone = input("请输入新电话号码 (留空保持不变): ")
                        update_address = input("请输入新地址 (留空保持不变): ")

                        phone = update_phone if update_phone else None
                        address = update_address if update_address else None

                        update_profile(token, phone, address)

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