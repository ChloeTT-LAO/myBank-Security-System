import time
import requests
import getpass
import pyotp
import os
from security.encryption import compute_hmac_sha256
from security.sign_verify import sign_data


def ensure_directory(directory):
    """确保目录存在"""
    if not os.path.exists(directory):
        os.makedirs(directory)


def employee_login(email: str, password: str):
    """员工登录"""
    print("\n=== 员工登录 ===")

    # 1. 构造签名消息
    timestamp = int(time.time())
    message = f"login|email={email}|timestamp={timestamp}"

    # 2. 读取私钥文件并签名
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"employee_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()
    except FileNotFoundError:
        print(f"错误: 找不到私钥文件 employee_secret/{safe_email}_private_key.pem")
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

    # 4. 发送登录请求 (使用通用的客户端登录端点)
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


def employee_logout(token: str):
    """员工登出"""
    print("\n=== 员工登出 ===")

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


def search_customer(token: str, email: str):
    """按邮箱搜索客户"""
    print(f"\n=== 搜索客户 {email} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送搜索请求...")
    url = f"https://127.0.0.1:5001/employee/customer/search?email={email}"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        customer = resp.json()
        print("客户信息:")
        print(f"  客户ID: {customer.get('customer_id')}")
        print(f"  邮箱: {customer.get('email')}")
        print(f"  角色: {customer.get('role')}")
        return customer
    else:
        print(f"搜索客户失败: {resp.text}")
        return None


def view_customer_accounts(token: str, customer_id: int):
    """查看客户的所有账户"""
    print(f"\n=== 查看客户 {customer_id} 的账户 ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送请求...")
    url = f"https://127.0.0.1:5001/employee/customer/{customer_id}/accounts"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        accounts = resp.json().get("accounts", [])
        print(f"客户 {customer_id} 有 {len(accounts)} 个账户:")
        for idx, account in enumerate(accounts, 1):
            print(f"\n账户 #{idx}:")
            for key, value in account.items():
                print(f"  {key}: {value}")
        return accounts
    else:
        print(f"查看客户账户失败: {resp.text}")
        return None


def view_account_transactions(token: str, account_id: int):
    """查看账户的交易记录"""
    print(f"\n=== 查看账户 {account_id} 的交易记录 ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("发送请求...")
    url = f"https://127.0.0.1:5001/employee/account/{account_id}/transactions"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        transactions = resp.json().get("transactions", [])
        print(f"账户 {account_id} 有 {len(transactions)} 条交易记录:")
        for idx, tx in enumerate(transactions, 1):
            print(f"\n交易 #{idx}:")
            for key, value in tx.items():
                print(f"  {key}: {value}")
        return transactions
    else:
        print(f"查看账户交易记录失败: {resp.text}")
        return None


def deposit_to_customer(token: str, account_id: int, amount: float, note: str = "Employee Deposit"):
    """代客户存款"""
    print(f"\n=== 向账户 {account_id} 存款 {amount} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {
        "account_id": account_id,
        "amount": amount,
        "note": note
    }

    print("发送存款请求...")
    url = "https://127.0.0.1:5001/employee/deposit"
    resp = requests.post(url, headers=headers, json=payload, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        print("存款成功!")
        print(f"交易ID: {data.get('transaction_id')}")
        return data
    else:
        print(f"存款失败: {resp.text}")
        return None


def withdraw_from_customer(token: str, account_id: int, amount: float, note: str = "Employee Withdrawal"):
    """代客户取款"""
    print(f"\n=== 从账户 {account_id} 取款 {amount} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {
        "account_id": account_id,
        "amount": amount,
        "note": note
    }

    print("发送取款请求...")
    url = "https://127.0.0.1:5001/employee/withdraw"
    resp = requests.post(url, headers=headers, json=payload, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        print("取款成功!")
        print(f"交易ID: {data.get('transaction_id')}")
        return data
    else:
        print(f"取款失败: {resp.text}")
        return None


def employee_transfer(token: str, source_account_id: int, destination_account_id: int, amount: float,
                      note: str = "Employee Transfer"):
    """代客户转账"""
    print(f"\n=== 从账户 {source_account_id} 转账 {amount} 到账户 {destination_account_id} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {
        "source_account_id": source_account_id,
        "destination_account_id": destination_account_id,
        "amount": amount,
        "note": note
    }

    print("发送转账请求...")
    url = "https://127.0.0.1:5001/employee/transfer"
    resp = requests.post(url, headers=headers, json=payload, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        print("转账成功!")
        print(f"交易ID: {data.get('transaction_id')}")
        return data
    else:
        print(f"转账失败: {resp.text}")
        return None


def update_customer_info(token: str, customer_id: int, phone: str = None, address: str = None):
    """更新客户信息"""
    print(f"\n=== 更新客户 {customer_id} 信息 ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {}
    if phone:
        payload["phone"] = phone
    if address:
        payload["address"] = address

    if not payload:
        print("错误: 至少需要提供一个要更新的字段")
        return False

    print("发送更新请求...")
    url = f"https://127.0.0.1:5001/employee/customer/{customer_id}/update"
    resp = requests.post(url, headers=headers, json=payload, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        print("客户信息更新成功!")
        return True
    else:
        print(f"客户信息更新失败: {resp.text}")
        return False


def mark_suspicious_transaction(token: str, transaction_id: int, reason: str):
    """标记可疑交易"""
    print(f"\n=== 标记交易 {transaction_id} 为可疑 ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {
        "reason": reason
    }

    print("发送标记请求...")
    url = f"https://127.0.0.1:5001/employee/transaction/{transaction_id}/mark_suspicious"
    resp = requests.post(url, headers=headers, json=payload, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        print("交易已标记为可疑!")
        return True
    else:
        print(f"标记交易失败: {resp.text}")
        return False


def freeze_account(token: str, account_id: int, reason: str):
    """冻结账户"""
    print(f"\n=== 冻结账户 {account_id} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {
        "reason": reason
    }

    print("发送冻结请求...")
    url = f"https://127.0.0.1:5001/employee/account/{account_id}/freeze"
    resp = requests.post(url, headers=headers, json=payload, verify=False)
    print(f"服务器响应: {resp.status_code}")

    if resp.status_code == 200:
        print("账户已冻结!")
        return True
    else:
        print(f"冻结账户失败: {resp.text}")
        return False


def employee_send_message(token: str, email: str, client_id: int, message_text: str):
    """员工向客户发送加密消息"""
    print(f"\n=== 向客户 {client_id} 发送加密消息 ===")

    # 1. 构造签名消息
    timestamp = int(time.time())
    message_str = f"send_message|email={email}|to={client_id}|content={message_text}|timestamp={timestamp}"

    # 2. 读取私钥和HMAC密钥
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"employee_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_key_pem = private_file.read()

        # 员工可能没有HMAC密钥文件，如果找不到，可以生成一个临时的
        try:
            with open(f"employee_secret/{safe_email}_hmac_key.txt", "rb") as hmac_file:
                hmac_key = hmac_file.read()
        except FileNotFoundError:
            hmac_key = os.urandom(32)  # 生成临时HMAC密钥
    except FileNotFoundError as e:
        print(f"错误: 找不到密钥文件 - {str(e)}")
        return None

    # 3. 生成签名和HMAC
    signature_bytes = sign_data(message_str.encode('utf-8'), private_key_pem)
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
    url = "https://127.0.0.1:5001/employee/message/send"
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


if __name__ == "__main__":
    print("==================== 欢迎使用MyBank员工客户端 ====================")

    # 确保密钥目录存在
    ensure_directory("employee_secret")

    # 登录
    email = input("请输入员工邮箱: ")
    password = getpass.getpass("请输入密码: ")

    token = employee_login(email, password)

    if token:
        # 登录成功，显示功能菜单
        while True:
            print("\n--- 员工功能菜单 ---")
            print("1. 客户管理")
            print("2. 账户操作")
            print("3. 交易监控")
            print("4. 安全管理")
            print("5. 通信")
            print("0. 登出")

            main_choice = input("请输入选项: ")

            if main_choice == "1":
                # 客户管理
                print("\n客户管理:")
                print("1. 搜索客户")
                print("2. 查看客户账户")
                print("3. 更新客户信息")
                print("0. 返回")

                sub_choice = input("请输入选项: ")

                if sub_choice == "1":
                    # 搜索客户
                    customer_email = input("请输入客户邮箱: ")
                    search_customer(token, customer_email)

                elif sub_choice == "2":
                    # 查看客户账户
                    customer_id = int(input("请输入客户ID: "))
                    view_customer_accounts(token, customer_id)

                elif sub_choice == "3":
                    # 更新客户信息
                    customer_id = int(input("请输入客户ID: "))
                    new_phone = input("请输入新电话 (留空保持不变): ")
                    new_address = input("请输入新地址 (留空保持不变): ")

                    phone = new_phone if new_phone else None
                    address = new_address if new_address else None

                    update_customer_info(token, customer_id, phone, address)

            elif main_choice == "2":
                # 账户操作
                print("\n账户操作:")
                print("1. 查看账户交易记录")
                print("2. 代客户存款")
                print("3. 代客户取款")
                print("4. 代客户转账")
                print("0. 返回")

                sub_choice = input("请输入选项: ")

                if sub_choice == "1":
                    # 查看账户交易记录
                    account_id = int(input("请输入账户ID: "))
                    view_account_transactions(token, account_id)

                elif sub_choice == "2":
                    # 代客户存款
                    account_id = int(input("请输入账户ID: "))
                    amount = float(input("请输入金额: "))
                    note = input("请输入备注 (可选): ") or "Employee Deposit"
                    deposit_to_customer(token, account_id, amount, note)

                elif sub_choice == "3":
                    # 代客户取款
                    account_id = int(input("请输入账户ID: "))
                    amount = float(input("请输入金额: "))
                    note = input("请输入备注 (可选): ") or "Employee Withdrawal"
                    withdraw_from_customer(token, account_id, amount, note)

                elif sub_choice == "4":
                    # 代客户转账
                    source_id = int(input("请输入源账户ID: "))
                    dest_id = int(input("请输入目标账户ID: "))
                    amount = float(input("请输入金额: "))
                    note = input("请输入备注 (可选): ") or "Employee Transfer"
                    employee_transfer(token, source_id, dest_id, amount, note)

            elif main_choice == "3":
                # 交易监控
                print("\n交易监控:")
                print("1. 标记可疑交易")
                print("2. 冻结账户")
                print("0. 返回")

                sub_choice = input("请输入选项: ")

                if sub_choice == "1":
                    # 标记可疑交易
                    tx_id = int(input("请输入交易ID: "))
                    reason = input("请输入标记原因: ")
                    mark_suspicious_transaction(token, tx_id, reason)

                elif sub_choice == "2":
                    # 冻结账户
                    account_id = int(input("请输入账户ID: "))
                    reason = input("请输入冻结原因: ")
                    freeze_account(token, account_id, reason)

            elif main_choice == "4":
                # 安全管理
                print("\n安全管理功能暂未实现")

            elif main_choice == "5":
                # 通信
                print("\n通信:")
                print("1. 向客户发送加密消息")
                print("0. 返回")

                sub_choice = input("请输入选项: ")

                if sub_choice == "1":
                    # 向客户发送加密消息
                    client_id = int(input("请输入客户ID: "))
                    message = input("请输入消息内容: ")
                    employee_send_message(token, email, client_id, message)

            elif main_choice == "0":
                # 登出
                if employee_logout(token):
                    break
            else:
                print("无效选项，请重试")
    else:
        print("登录失败，程序退出")