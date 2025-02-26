import requests
import base64
from security.encryption import generate_rsa_keypair, serialize_private_key_to_pem, serialize_public_key_to_pem


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
    url = "https://127.0.0.1:5001/admin/keys/new_rsa"
    # 因为是自签名证书，需要用 verify=False 或指定证书
    resp = requests.post(url, verify=False)
    print(resp)


def generate_new_ase(key_name, key_type, expiry_days, key_version):
    payload = {
        "key_name": key_name,
        "key_type": key_type,
        "expiry_days": expiry_days,
        "key_version":key_version
    }
    url = "https://127.0.0.1:5001/admin/keys/new_aes"
    # 因为是自签名证书，需要用 verify=False 或指定证书
    resp = requests.post(url, json=payload, verify=False)
    print(resp)


if __name__ == '__main__':
    # generate_new_rsa()
    generate_new_ase("user_transaction", "symmetric", 30, "v1")
    # name = "Admin"
    # password = "admin"
    # email = "admin@gmail.com"
    # role = "system_admin"
    # phone = "987654320"
    # address = "admin road"
    # employee_creation(name, email, password, phone, address, role)