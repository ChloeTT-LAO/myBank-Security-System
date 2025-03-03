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

    ensure_directory("user_secret")

    # 1. Generate a local RSA key pair
    print("Generate an RSA key pair...")
    private_key, public_key = generate_rsa_keypair()
    private_pem = serialize_private_key_to_pem(private_key)
    public_pem = serialize_public_key_to_pem(public_key)

    # Save the private key to a file
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    with open(f"user_secret/{safe_email}_private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
        private_file.close()
    print(f"The private key is saved to user_secret/{safe_email}_private_key.pem")

    # 2. Construct request body
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

    # 3. Send a registration request
    print("Send a registration request...")
    url = "https://127.0.0.1:5001/client/register"
    resp = requests.post(url, json=payload, headers=headers, verify='certificate/cert.pem')
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 201:
        resp_data = resp.json()
        totp_secret = resp_data.get("totp_secret")
        hmac_key = resp_data.get("hmac_key")

        # Save the TOTP key
        if totp_secret:
            with open(f"user_secret/{safe_email}_totp_secret.txt", "w") as f:
                f.write(totp_secret)
            print(f"TOTP key is saved to user_secret/{safe_email}_totp_secret.txt")

            # The TOTP QR code URL is displayed
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=email, issuer_name="MyBank")
            print(f"TOTP URI: {totp_uri}")
            print("Use Google Authenticator or another TOTP application to scan this URI to set up two-factor authentication")

        # Save the HMAC key
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
    """user logout"""
    print("\n=== User Logout ===")

    url = "https://127.0.0.1:5001/client/logout"
    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Send a logout request...")
    resp = requests.post(url, headers=headers, json={}, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        print("Logout success！")
        return True
    else:
        print(f"Logout failure: {resp.text}")
        return False


def user_create_account(email: str, account_type: str, token: str, ip_address: str = None,
                  user_agent: str = None):
    """ create a new account """
    print("\n=== create a new account ===")

    timestamp = int(time.time())
    message = f"create_account|email={email}|account_type={account_type}|timestamp={timestamp}"

    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()

        with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as hmac_file:
            hmac_key = hmac_file.read()
    except FileNotFoundError as e:
        print(f"Error: Key file not found - {str(e)}")
        return None

    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()
    hmac_value = compute_hmac_sha256(message.encode('utf-8'), base64.b64decode(hmac_key))

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
    """Deposit operation"""
    print(f"\n=== Deposit {amount} to account {account_number} ===")

    timestamp = int(time.time())
    message = f"deposit|email={email}|account_number={account_number}|amount={amount}|timestamp={timestamp}"

    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()

        with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as hmac_file:
            hmac_key = hmac_file.read()
    except FileNotFoundError as e:
        print(f"Error: Key file not found - {str(e)}")
        return None

    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()
    hmac_value = compute_hmac_sha256(message.encode('utf-8'), hmac_key)

    payload = {
        "message": message,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Send a deposit request...")
    url = "https://127.0.0.1:5001/client/transaction/deposit"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        transaction_id = data.get("transaction_id")
        balance = data.get("balance")
        print(f"Deposit success! Transaction ID: {transaction_id}")
        print(f"current balance: {balance}")
        return transaction_id, balance
    else:
        print(f"Deposit failure: {resp.text}")
        return None, None


def user_withdraw(email: str, account_number: str, amount: str, token: str):
    """Withdraw operation"""
    print(f"\n=== Withdraw from {account_number}: {amount} ===")

    timestamp = int(time.time())
    message = f"withdraw|email={email}|account_number={account_number}|amount={amount}|timestamp={timestamp}"

    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()

        with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as hmac_file:
            hmac_key = hmac_file.read()
    except FileNotFoundError as e:
        print(f"Error: Key file not found - {str(e)}")
        return None

    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()
    hmac_value = compute_hmac_sha256(message.encode('utf-8'), hmac_key)

    payload = {
        "message": message,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Send a withdrawal request...")
    url = "https://127.0.0.1:5001/client/transaction/withdraw"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        transaction_id = data.get("transaction_id")
        balance = data.get("balance")
        print(f"Withdrawal successful! Transaction ID: {transaction_id}")
        print(f"current balance: {balance}")
        return transaction_id, balance
    else:
        print(f"Withdrawal failure: {resp.text}")
        return None, None


def user_transfer(email: str, source_account_number: str, destination_account_number: str, amount: str, token: str):
    """Transfer"""
    print(f"\n=== From account {source_account_number} transfer {amount} to account {destination_account_number} ===")

    timestamp = int(time.time())
    message = f"transfer|email={email}|source_account_number={source_account_number}|destination_account_number={destination_account_number}|amount={amount}|timestamp={timestamp}"

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

    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()
    hmac_value = compute_hmac_sha256(message.encode('utf-8'), base64.b64decode(hmac_key))

    payload = {
        "message": message,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Send a transfer request...")
    url = "https://127.0.0.1:5001/client/transaction/transfer"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    # Check if additional verification is required (high risk transactions)
    if resp.status_code == 428:  # Requests require additional validation
        print("High risk transactions require additional verification...")

        verification_code = 000

        # Add capTCHA and re-request
        payload["verification_code"] = verification_code
        resp = requests.post(url, json=payload, headers=headers, verify=False)
        print(f"The server responds after verification: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        transaction_id = data.get("transaction_id")
        balance = data.get("balance")
        print(f"Transfer successful! Transaction ID: {transaction_id}")
        print(f"current balance: {balance}")
        return transaction_id, balance
    else:
        print(f"Transfer failure: {resp.text}")
        return None, None


def client_send_message(email: str, employee_id: int, message_text: str, token: str):
    """Send encrypted messages to bank employees"""
    print(f"\n=== Send encrypted message to {employee_id} ===")

    timestamp = int(time.time())
    message_str = f"send_message|email={email}|to={employee_id}|content={message_text}|timestamp={timestamp}"

    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"user_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()

        with open(f"user_secret/{safe_email}_hmac_key.txt", "rb") as hmac_file:
            hmac_key = hmac_file.read()
    except FileNotFoundError as e:
        print(f"Error: Key file not found - {str(e)}")
        return None

    signature_bytes = sign_data(message_str.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()
    hmac_value = compute_hmac_sha256(message_str.encode('utf-8'), base64.b64decode(hmac_key))

    payload = {
        "message": message_str,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Sending encrypted message...")
    url = "https://127.0.0.1:5001/client/message/send"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"Server respond: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        message_id = data.get("message_id")
        print(f"Send message successfully! Message ID: {message_id}")
        return message_id
    else:
        print(f"Fail to send message: {resp.text}")
        return None


def get_account_info(token: str, account_id: int):
    """Retrieve account information"""
    print(f"\n=== Retrieving account {account_id} information ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Sending request...")
    url = f"https://127.0.0.1:5001/client/account/{account_id}/info"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        info = resp.json()
        print("Account information:")
        for key, value in info.items():
            print(f"  {key}: {value}")
        return info
    else:
        print(f"Failed to retrieve account information: {resp.text}")
        return None


def get_transaction_history(token: str, account_id: int):
    """Retrieve transaction history"""
    print(f"\n=== Retrieving transaction history for account {account_id} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Sending request...")
    url = f"https://127.0.0.1:5001/client/account/{account_id}/transactions"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        transactions = resp.json().get("transactions", [])
        print(f"Found {len(transactions)} transaction records:")
        for idx, tx in enumerate(transactions, 1):
            print(f"\nTransaction #{idx}:")
            for key, value in tx.items():
                print(f"  {key}: {value}")
        return transactions
    else:
        print(f"Failed to retrieve transaction history: {resp.text}")
        return None


def change_password(token: str, current_password: str, new_password: str):
    """Change password"""
    print("\n=== Changing password ===")

    payload = {
        "action": "change_password",
        "current_password": current_password,
        "new_password": new_password
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Sending password change request...")
    url = "https://127.0.0.1:5001/client/security"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        print("Password changed successfully!")
        return True
    else:
        print(f"Password change failed: {resp.text}")
        return False


def update_profile(token: str, phone: str = None, address: str = None):
    """Update profile information"""
    print("\n=== Updating profile information ===")

    payload = {}
    if phone:
        payload["phone"] = phone
    if address:
        payload["address"] = address

    if not payload:
        print("Error: At least one field must be provided for update")
        return False

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Sending profile update request...")
    url = "https://127.0.0.1:5001/client/profile/update"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        print("Profile updated successfully!")
        return True
    else:
        print(f"Profile update failed: {resp.text}")
        return False



def register_webauthn(email, token):
    """Register WebAuthn credentials"""
    print("\n=== Register WebAuthn credentials ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = "https://127.0.0.1:5001/client/webauthn/register"
    resp = requests.post(url, headers=headers, json={}, verify=False)
    print(f"Server Respond: {resp.status_code}")

    if resp.status_code == 200:
        options = resp.json().get("options")

        print("Complete the WebAuthn registration in your browser...")
        print("Registration option:", json.dumps(options, indent=2))

        # Simulate the credentials returned by the browser
        # In practice, this should be generated by the browser's WebAuthn API
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
                        "rpIdHash": base64.b64encode(hashlib.sha256(b"bankingsystem.example.com").digest()).decode('ascii'),
                        "flags": 0x41,  # AT and UP flags
                        "counter": 1,
                        "attestedCredentialData": {
                            "aaguid": base64.b64encode(os.urandom(16)).decode('ascii'),
                            "credentialId": base64.b64encode(os.urandom(32)).decode('ascii'),
                            "credentialPublicKey": base64.b64encode(os.urandom(65)).decode('ascii')
                        }
                    }
                }
            }
        }

        # Verify registration
        verify_url = "https://127.0.0.1:5001/client/webauthn/register/verify"
        verify_resp = requests.post(
            verify_url,
            headers=headers,
            json={"credential": credential},
            verify=False
        )
        print(f"Validation response: {verify_resp.status_code}")
        print(verify_resp.json())

        return verify_resp.json()
    else:
        print(f"fail to register: {resp.text}")
        return None


def webauthn_login(email):
    """WebAuthn Login"""
    print("\n=== WebAuthn Login ===")

    url = "https://127.0.0.1:5001/client/webauthn/login"
    resp = requests.post(url, json={"username": email}, verify=False)
    print(f"Server respond: {resp.status_code}")

    if resp.status_code == 200:
        options = resp.json().get("options")

        print("Complete WebAuthn verification in your browser...")
        print("Validation option:", json.dumps(options, indent=2))

        # Simulate the credentials returned by the browser
        # In practice, this should be generated by the browser's WebAuthn API
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

        # verify login
        verify_url = "https://127.0.0.1:5001/client/webauthn/login/verify"
        verify_resp = requests.post(
            verify_url,
            json={
                "username": email,
                "credential": credential
            },
            verify=False
        )
        print(f"Validation response: {verify_resp.status_code}")

        if verify_resp.status_code == 200:
            token = verify_resp.json().get("token")
            print("login successfully!")
            return token
        else:
            print(f"login failure: {verify_resp.text}")
            return None
    else:
        print(f"Login request failed: {resp.text}")
        return None


def test_risk_behavior(email, token):
    """Test user behavior risk assessment"""
    print("\n=== Testing Behavior Risk Assessment ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    # 1. Perform a few normal transactions to establish a baseline
    print("Performing a few normal transactions to establish a baseline...")

    # Create account
    account_type = "checking"
    resp = user_create_account(email, account_type, token)
    if resp.status_code != 201:
        print("Account creation failed")
        return

    account_number = resp.json().get("account_number")

    # Deposit
    amount = "1000"
    resp = user_deposit(email, account_number, amount, token)
    if resp.status_code != 200:
        print("Deposit failed")
        return

    # Query balance multiple times to establish normal behavior pattern
    for _ in range(3):
        url = f"https://127.0.0.1:5001/client/account/1/info"
        requests.get(url, headers=headers, verify=False)
        time.sleep(1)

    print("Baseline established")

    # 2. Test abnormal behavior - Large transfer
    print("\nTesting abnormal behavior - Large transfer...")

    # Create second account
    resp = user_create_account(email, "savings", token)
    if resp.status_code != 201:
        print("Second account creation failed")
        return

    second_account = resp.json().get("account_number")

    # Attempt large transfer (should trigger additional verification)
    large_amount = "900"
    resp = user_transfer(email, account_number, second_account, large_amount, token)

    print(f"Transfer response: {resp.status_code}")
    print(resp.json())

    if resp.status_code == 428:  # Requires additional verification
        print("System correctly identified high-risk transaction and requested additional verification!")
    else:
        print("Additional verification not triggered, risk assessment threshold may not have been met")

    return resp.json()


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
                        account_number = input("Please enter your account number: ")
                        amount = input("Please enter the amount: ")
                        user_deposit(email, account_number, amount, token)

                    elif sub_choice == "3":
                        account_number = input("Please enter your account number: ")
                        amount = input("Please enter the amount: ")
                        user_withdraw(email, account_number, amount, token)

                    elif sub_choice == "4":
                        source_account = input("Please enter the source account number: ")
                        destination_account = input("Please enter the target account number: ")
                        amount = input("Please enter the amount: ")
                        user_transfer(email, source_account, destination_account, amount, token)

                    elif sub_choice == "5":
                        account_id = int(input("Enter account ID: "))
                        get_account_info(token, account_id)

                    elif sub_choice == "6":
                        account_id = int(input("Enter account ID: "))
                        get_transaction_history(token, account_id)

                    elif sub_choice == "7":
                        employee_id = int(input("Please enter your bank clerk ID: "))
                        message = input("Please enter the message content: ")
                        client_send_message(email, employee_id, message, token)

                    elif sub_choice == "8":
                        # security settings
                        print("\nsecurity settings:")
                        print("1. change password")
                        print("2. change TOTP")
                        print("0. return")

                        security_choice = input("Please enter options: ")

                        if security_choice == "1":
                            current_password = getpass.getpass("Please enter your current password: ")
                            new_password = getpass.getpass("Please enter your new password: ")
                            confirm_password = getpass.getpass("Please confirm the new password: ")

                            if new_password != confirm_password:
                                print("Error: The two new passwords do not match")
                            else:
                                change_password(token, current_password, new_password)

                    elif sub_choice == "9":
                        # update profile
                        update_phone = input("Please enter new phone number (leave blank): ")
                        update_address = input("Please enter new address (leave blank): ")

                        phone = update_phone if update_phone else None
                        address = update_address if update_address else None

                        update_profile(token, phone, address)

                    elif sub_choice == "10":
                        # Register WebAuthn credentials
                        register_webauthn(email, token)

                    elif sub_choice == "11":
                        # Test behavioral risk assessment
                        test_risk_behavior(email, token)

                    elif sub_choice == "0":
                        # logout
                        if user_logout(token):
                            break
                    else:
                        print("Invalid option, please try again")

        elif main_choice == "0":
            print("Thanks for using MyBank client, bye!")
            break

        else:
            print("Invalid option, please try again")
