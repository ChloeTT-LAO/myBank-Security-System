import requests
import base64
import time
import getpass
from security.encryption import generate_rsa_keypair, serialize_private_key_to_pem, serialize_public_key_to_pem
from security.sign_verify import sign_data


def employee_creation(name: str, email: str, password: str, phone: str, address: str, role: str):
    # 1. 生成本地RSA密钥对 (演示)
    private_key, public_key = generate_rsa_keypair()
    private_pem = serialize_private_key_to_pem(private_key)
    public_pem = serialize_public_key_to_pem(public_key)

    # 保存私钥到文件（以二进制模式写入）
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"employee_secret/{safe_email}_private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
        private_file.close()

    # 4. 构造请求体
    payload = {
        "name": name,
        "address": address,
        "phone": phone,
        "password": password,
        "email": email,
        "public_key": base64.b64encode(public_pem).decode(),
        "role": role
    }

    # 5. 向HTTPS服务器发起POST请求
    url = "https://127.0.0.1:5001/admin/register"
    # 因为是自签名证书，需要用 verify=False 或指定证书
    resp = requests.post(url, json=payload, verify=False)
    resp_data = resp.json()
    totp_secret = resp_data.get("totp_secret")
    if totp_secret:
        # 把 totp_secret 写入本地文件
        with open(f"employee_secret/{safe_email}_totp_secret.txt", "w") as f:
            f.write(totp_secret)
        print("TOTP secret saved to totp_secret.txt")
    else:
        print("No totp_secret found in response.")
    print(resp)


def generate_new_rsa():
    """生成新的RSA密钥对"""
    url = "https://127.0.0.1:5001/admin/keys/new_rsa"
    # 因为是自签名证书，需要用 verify=False 或指定证书
    resp = requests.post(url, verify=False)
    print("Response status:", resp.status_code)
    print("Response body:", resp.text)
    return resp


def generate_new_aes(key_name, key_type, expiry_days, key_version):
    """生成新的AES密钥"""
    payload = {
        "key_name": key_name,
        "key_type": key_type,
        "expiry_days": expiry_days,
        "key_version": key_version
    }
    url = "https://127.0.0.1:5001/admin/keys/new_aes"
    resp = requests.post(url, json=payload, verify=False)
    print("Response status:", resp.status_code)
    print("Response body:", resp.text)
    return resp


# 新增密钥管理功能

def admin_login(email: str, password: str):
    """管理员登录"""
    timestamp = int(time.time())
    message = f"login|email={email}|timestamp={timestamp}"

    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"employee_secret/{safe_email}_private_key.pem", "rb") as private_file:
        private_pem = private_file.read()
    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()

    payload = {
        "message": message,
        "signature": signature_hex,
        "email": email,
        "password": password
    }

    url = "https://127.0.0.1:5001/client/login"  # 使用通用登录端点
    resp = requests.post(url, json=payload, verify=False)
    print("Login Response:", resp.status_code, resp.text)

    if resp.status_code == 200:
        return resp.json().get("token")
    return None


def list_all_keys(token, include_expired=False):
    """列出所有密钥"""
    url = f"https://127.0.0.1:5001/admin/keys?include_expired={str(include_expired).lower()}"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    resp = requests.get(url, headers=headers, verify=False)
    print(f"List keys response (include_expired={include_expired}):")
    if resp.status_code == 200:
        keys = resp.json().get("keys", [])
        for key in keys:
            print(
                f"Key ID: {key.get('key_id')}, Name: {key.get('key_name')}, Version: {key.get('key_version')}, Status: {key.get('status')}")
    else:
        print("Error:", resp.text)
    return resp


def backup_keys(token, backup_password, backup_location="key_backups"):
    """备份所有密钥"""
    url = "https://127.0.0.1:5001/admin/keys/backup"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    payload = {
        "backup_password": backup_password,
        "backup_location": backup_location
    }
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print("Backup keys response:")
    print(resp.text)
    return resp


def restore_keys(token, backup_file, backup_password):
    """从备份恢复密钥"""
    url = "https://127.0.0.1:5001/admin/keys/restore"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    payload = {
        "backup_file": backup_file,
        "backup_password": backup_password
    }
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print("Restore keys response:")
    print(resp.text)
    return resp


def rotate_key(token, key_id, key_type="symmetric", expiry_days=30):
    """轮换指定密钥"""
    url = "https://127.0.0.1:5001/admin/keys/rotate"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    payload = {
        "key_id": key_id,
        "key_type": key_type,
        "expiry_days": expiry_days
    }
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print("Rotate key response:")
    print(resp.text)
    return resp


def admin_key_management_menu(token):
    """管理员密钥管理菜单"""
    while True:
        print("\n===== 密钥管理系统 =====")
        print("1. 列出所有密钥")
        print("2. 生成新的RSA密钥对")
        print("3. 生成新的AES密钥")
        print("4. 轮换密钥")
        print("5. 备份所有密钥")
        print("6. 从备份恢复密钥")
        print("0. 返回主菜单")

        choice = input("请选择操作: ")

        if choice == "1":
            include_expired = input("是否包含已过期密钥? (y/n): ").lower() == 'y'
            list_all_keys(token, include_expired)

        elif choice == "2":
            generate_new_rsa()

        elif choice == "3":
            key_name = input("请输入密钥名称: ")
            key_type = input("请输入密钥类型 [默认: symmetric]: ") or "symmetric"
            key_version = input("请输入密钥版本 [默认: v1]: ") or "v1"
            expiry_days = int(input("请输入密钥有效期(天) [默认: 30]: ") or "30")
            generate_new_aes(key_name, key_type, expiry_days, key_version)

        elif choice == "4":
            # 先列出所有密钥供选择
            list_resp = list_all_keys(token, False)
            if list_resp.status_code != 200:
                continue

            key_id = int(input("请输入要轮换的密钥ID: "))
            key_type = input("请输入密钥类型 [默认: symmetric]: ") or "symmetric"
            expiry_days = int(input("请输入新密钥有效期(天) [默认: 30]: ") or "30")
            rotate_key(token, key_id, key_type, expiry_days)

        elif choice == "5":
            backup_location = input("请输入备份位置 [默认: key_backups]: ") or "key_backups"
            backup_password = getpass.getpass("请输入备份密码: ")
            backup_keys(token, backup_password, backup_location)

        elif choice == "6":
            backup_file = input("请输入备份文件路径: ")
            backup_password = getpass.getpass("请输入备份密码: ")
            restore_keys(token, backup_file, backup_password)

        elif choice == "0":
            break

        else:
            print("无效选择，请重试")


if __name__ == '__main__':
    print("==================== MyBank 管理员工具 ====================")
    print("1. 创建员工/管理员账户")
    print("2. 管理员登录")
    print("3. 密钥管理")
    print("0. 退出")

    choice = input("请选择操作: ")

    if choice == "1":
        name = input("输入姓名: ")
        email = input("输入邮箱: ")
        password = input("输入密码: ")
        phone = input("输入电话: ")
        address = input("输入地址: ")
        role = input("输入角色 (system_admin/bank_employee): ")
        employee_creation(name, email, password, phone, address, role)

    elif choice == "2":
        email = input("输入管理员邮箱: ")
        password = getpass.getpass("输入密码: ")
        token = admin_login(email, password)

        if token:
            print("登录成功!")
            admin_key_management_menu(token)
        else:
            print("登录失败!")

    elif choice == "3":
        # 简化演示，直接执行密钥生成
        key_name = input("请输入密钥名称: ")
        key_version = input("请输入密钥版本 [默认: v1]: ") or "v1"
        generate_new_aes(key_name, "symmetric", 30, key_version)

    elif choice == "0":
        print("谢谢使用，再见!")

    else:
        print("无效选择，请重试")