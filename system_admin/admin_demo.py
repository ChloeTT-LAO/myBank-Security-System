import os

import pyotp
import requests
import base64
import time
import getpass
from security.encryption import generate_rsa_keypair, serialize_private_key_to_pem, serialize_public_key_to_pem
from security.sign_verify import sign_data


def ensure_directory(directory):
    """Ensure directory existence"""
    if not os.path.exists(directory):
        os.makedirs(directory)


def employee_creation(name: str, email: str, password: str, phone: str, address: str, role: str, ip_address: str = None,
                  user_agent: str = None):

    print("\n=== Register a new employee/admin ===")

    # Ensure storage directory exists
    ensure_directory("employee_secret")

    # 1. Generate local RSA key pair
    print("Generate an RSA key pair...")
    private_key, public_key = generate_rsa_keypair()
    private_pem = serialize_private_key_to_pem(private_key)
    public_pem = serialize_public_key_to_pem(public_key)

    # Save private key to file
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"employee_secret/{safe_email}_private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
        private_file.close()
    print(f"The private key is saved to employee_secret/{safe_email}_private_key.pem")

    # 2. Construct request body
    payload = {
        "name": name,
        "address": address,
        "phone": phone,
        "password": password,
        "email": email,
        "role": role,
        "public_key": base64.b64encode(public_pem).decode()
    }

    headers = {}
    if ip_address:
        headers["X-Test-IP"] = ip_address
    if user_agent:
        headers["User-Agent"] = user_agent

    # 3. Send registration request
    print("Send a registration request...")
    url = "https://127.0.0.1:5001/admin/register"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 201:
        resp_data = resp.json()
        totp_secret = resp_data.get("totp_secret")
        hmac_key = resp_data.get("hmac_key")

        # Save TOTP key
        if totp_secret:
            with open(f"employee_secret/{safe_email}_totp_secret.txt", "w") as f:
                f.write(totp_secret)
            print(f"TOTP key is saved to employee_secret/{safe_email}_totp_secret.txt")

            # Display TOTP QR code URL
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=email, issuer_name="MyBank")
            print(f"TOTP URI: {totp_uri}")
            print("Use Google Authenticator or another TOTP application to scan this URI to set up two-factor authentication")

        # Save HMAC key
        if hmac_key:
            with open(f"employee_secret/{safe_email}_hmac_key.txt", "wb") as f:
                f.write(base64.b64decode(hmac_key))
            print(f"HMAC key is saved to employee_secret/{safe_email}_hmac_key.txt")

        print("Registered successfully! Please keep your key file safe and do not disclose it to others.")
    else:
        print(f"Fail to register: {resp.text}")


def generate_new_rsa():
    """Generate a new RSA key pair"""
    url = "https://127.0.0.1:5001/admin/keys/new_rsa"
    # Because it's a self-signed certificate, need to use verify=False or specify the certificate
    resp = requests.post(url, verify=False)
    print("Response status:", resp.status_code)
    print("Response body:", resp.text)
    return resp


def generate_new_aes(key_name, key_type, expiry_days, key_version):
    """Generate a new AES key"""
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


# New key management functions

def admin_login(email: str, password: str):
    """Admin login"""
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

    url = "https://127.0.0.1:5001/client/login"  # Use common login endpoint
    resp = requests.post(url, json=payload, verify=False)
    print("Login Response:", resp.status_code, resp.text)

    if resp.status_code == 200:
        return resp.json().get("token")
    return None


def list_all_keys(token, include_expired=False):
    """List all keys"""
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
    """Backup all keys"""
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
    """Restore keys from backup"""
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
    """Rotate specified key"""
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
    """Administrator key management menu"""
    while True:
        print("\n===== key management system =====")
        print("1. List all keys")
        print("2. Example Generate a new RSA key pair")
        print("3. Generate a new AES key")
        print("4. Alternate key")
        print("5. Back up all keys")
        print("6. Restore key from backup")
        print("0. Back to main menu")

        choice = input("Please select operation: ")

        if choice == "1":
            include_expired = input("Whether to contain an expired key? (y/n): ").lower() == 'y'
            list_all_keys(token, include_expired)

        elif choice == "2":
            generate_new_rsa()

        elif choice == "3":
            key_name = input("Please enter the key name: ")
            key_type = input("Please enter the key type [Default: symmetric]: ") or "symmetric"
            key_version = input("Please enter the key version [Default: v1]: ") or "v1"
            expiry_days = int(input("Please enter the key validity period (days) [Default: 30]: ") or "30")
            generate_new_aes(key_name, key_type, expiry_days, key_version)

        elif choice == "4":
            # List all keys to choose from first
            list_resp = list_all_keys(token, False)
            if list_resp.status_code != 200:
                continue

            key_id = int(input("Please enter the key ID you want to rotate: "))
            key_type = input("Please enter the key type [Default: symmetric]: ") or "symmetric"
            expiry_days = int(input("Please enter the new key validity period (days) [Default: 30]: ") or "30")
            rotate_key(token, key_id, key_type, expiry_days)

        elif choice == "5":
            backup_location = input("Please enter backup location [Default: key_backups]: ") or "key_backups"
            backup_password = getpass.getpass("Please enter the backup password: ")
            backup_keys(token, backup_password, backup_location)

        elif choice == "6":
            backup_file = input("Please enter the backup file path: ")
            backup_password = getpass.getpass("Please enter the backup password: ")
            restore_keys(token, backup_file, backup_password)

        elif choice == "0":
            break

        else:
            print("Invalid selection, please try again")


def get_blockchain_status(token):
    """Get blockchain status"""
    print("\n=== Get blockchain status ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = "https://127.0.0.1:5001/admin/blockchain/status"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"Server respond: {resp.status_code}")

    if resp.status_code == 200:
        status = resp.json().get("status")
        print("Blockchain state:")
        print(f"  Block number: {status.get('block_count')}")
        print(f"  Number of transaction: {status.get('transaction_count')}")
        print(f"  Pending transaction: {status.get('pending_count')}")

        last_block = status.get('last_block', {})
        print("Latest block:")
        print(f"  Block ID:: {last_block.get('block_id')}")
        print(f"  Block Hash: {last_block.get('block_hash')}")
        print(f"  Timestamp: {last_block.get('timestamp')}")

        return status
    else:
        print(f"Failure: {resp.text}")
        return None


def verify_blockchain_transaction(token, transaction_id):
    """Verify blockchain transactions"""
    print(f"\n=== Verify blockchain transactions {transaction_id} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = f"https://127.0.0.1:5001/admin/blockchain/verify/{transaction_id}"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"Server respond: {resp.status_code}")

    if resp.status_code == 200:
        result = resp.json().get("result")
        verified = result.get("verified", False)

        if verified:
            print("√ Transaction verification successful!")
            print(f"  Block ID: {result.get('block_id')}")
            print(f"  Block Hash: {result.get('block_hash')}")
            print(f"  Timestamp: {result.get('timestamp')}")
        else:
            print("✗ Transaction verification failure!")
            print(f"  Reason: {result.get('message')}")

        return result
    else:
        print(f"Validation failure: {resp.text}")
        return None


def admin_blockchain_menu(token):
    """Admin Blockchain management menu"""
    while True:
        print("\n===== Blockchain management =====")
        print("1. View blockchain status")
        print("2. Verify transaction")
        print("0. Back to main menu")

        choice = input("Please select operation: ")

        if choice == "1":
            # View blockchain status
            get_blockchain_status(token)

        elif choice == "2":
            # Verify transaction
            transaction_id = int(input("Enter transaction ID: "))
            verify_blockchain_transaction(token, transaction_id)

        elif choice == "0":
            break

        else:
            print("Invalid option, please try again")


if __name__ == '__main__':
    print("==================== MyBank Administrator Tools ====================")
    print("1. Create an employee/administrator account")
    print("2. Administrator login")
    print("0. Logout")

    choice = input("Please select operation: ")

    if choice == "1":
        name = input("Enter name: ")
        email = input("Enter email: ")
        password = input("Enter password: ")
        phone = input("Enter phone: ")
        address = input("Enter address: ")
        role = input("Enter role (system_admin/bank_employee): ")
        employee_creation(name, email, password, phone, address, role)

    elif choice == "2":
        email = input("Enter administrator email: ")
        password = getpass.getpass("Enter password: ")
        token = admin_login(email, password)

        if token:
            print("login successfully!")
            # The login succeeds, and the function menu is displayed
            while True:
                print("\n--- Admin function menu ---")
                print("1. Key management")
                print("2. Blockchain management")
                print("3. Logout")
                sub_choice = input("Please enter options: ")
                if sub_choice == "1":
                    admin_key_management_menu(token)

                elif sub_choice == "2":
                    admin_blockchain_menu(token)

                else:
                    print("Thanks for using, bye!")
                    break
        else:
            print("login failure!")