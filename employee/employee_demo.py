import time
import requests
import getpass
import pyotp
import os
from security.encryption import compute_hmac_sha256
from security.sign_verify import sign_data


def ensure_directory(directory):
    """Ensure directory exists"""
    if not os.path.exists(directory):
        os.makedirs(directory)


def employee_login(email: str, password: str):
    """Employee login"""
    print("\n=== Employee Login ===")

    # 1. Construct signature message
    timestamp = int(time.time())
    message = f"login|email={email}|timestamp={timestamp}"

    # 2. Read private key file and sign
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"employee_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_pem = private_file.read()
    except FileNotFoundError:
        print(f"Error: Private key file not found employee_secret/{safe_email}_private_key.pem")
        return None

    signature_bytes = sign_data(message.encode('utf-8'), private_pem)
    signature_hex = signature_bytes.hex()

    # 3. Construct request payload
    payload = {
        "message": message,
        "signature": signature_hex,
        "email": email,
        "password": password
    }

    # 4. Send login request (using common client login endpoint)
    print("Sending login request...")
    url = "https://127.0.0.1:5001/client/login"
    resp = requests.post(url, json=payload, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        token = resp.json().get("token")
        print("Login successful!")
        return token
    else:
        print(f"Login failed: {resp.text}")
        return None


def employee_logout(token: str):
    """Employee logout"""
    print("\n=== Employee Logout ===")

    url = "https://127.0.0.1:5001/client/logout"
    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Sending logout request...")
    resp = requests.post(url, headers=headers, json={}, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        print("Logout successful!")
        return True
    else:
        print(f"Logout failed: {resp.text}")
        return False


def search_customer(token: str, email: str):
    """Search customer by email"""
    print(f"\n=== Search customer {email} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Sending search request...")
    url = f"https://127.0.0.1:5001/employee/customer/search?email={email}"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        customer = resp.json()
        print("Customer information:")
        print(f"  Customer ID: {customer.get('customer_id')}")
        print(f"  Email: {customer.get('email')}")
        print(f"  Role: {customer.get('role')}")
        return customer
    else:
        print(f"Search customer failed: {resp.text}")
        return None


def view_customer_accounts(token: str, customer_id: int):
    """View all accounts of a customer"""
    print(f"\n=== View accounts for customer {customer_id} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Sending request...")
    url = f"https://127.0.0.1:5001/employee/customer/{customer_id}/accounts"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        accounts = resp.json().get("accounts", [])
        print(f"Customer {customer_id} has {len(accounts)} accounts:")
        for idx, account in enumerate(accounts, 1):
            print(f"\nAccount #{idx}:")
            for key, value in account.items():
                print(f"  {key}: {value}")
        return accounts
    else:
        print(f"Viewing customer accounts failed: {resp.text}")
        return None


def view_account_transactions(token: str, account_id: int):
    """View transactions for an account"""
    print(f"\n=== View transactions for account {account_id} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Sending request...")
    url = f"https://127.0.0.1:5001/employee/account/{account_id}/transactions"
    resp = requests.get(url, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        transactions = resp.json().get("transactions", [])
        print(f"Account {account_id} has {len(transactions)} transactions:")
        for idx, tx in enumerate(transactions, 1):
            print(f"\nTransaction #{idx}:")
            for key, value in tx.items():
                print(f"  {key}: {value}")
        return transactions
    else:
        print(f"Viewing account transactions failed: {resp.text}")
        return None


def employee_transfer(token: str, source_account_id: int, destination_account_id: int, amount: float,
                      note: str = "Employee Transfer"):
    """Transfer on behalf of customer"""
    print(f"\n=== Transfer {amount} from account {source_account_id} to account {destination_account_id} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {
        "source_account_id": source_account_id,
        "destination_account_id": destination_account_id,
        "amount": amount,
        "note": note
    }

    print("Sending transfer request...")
    url = "https://127.0.0.1:5001/employee/transfer"
    resp = requests.post(url, headers=headers, json=payload, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        print("Transfer successful!")
        print(f"Transaction ID: {data.get('transaction_id')}")
        return data
    else:
        print(f"Transfer failed: {resp.text}")
        return None


def update_customer_info(token: str, customer_id: int, phone: str = None, address: str = None):
    """Update customer information"""
    print(f"\n=== Update information for customer {customer_id} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {}
    if phone:
        payload["phone"] = phone
    if address:
        payload["address"] = address

    if not payload:
        print("Error: At least one field to update must be provided")
        return False

    print("Sending update request...")
    url = f"https://127.0.0.1:5001/employee/customer/{customer_id}/update"
    resp = requests.post(url, headers=headers, json=payload, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        print("Customer information updated successfully!")
        return True
    else:
        print(f"Customer information update failed: {resp.text}")
        return False


def mark_suspicious_transaction(token: str, transaction_id: int, reason: str):
    """Mark suspicious transaction"""
    print(f"\n=== Mark transaction {transaction_id} as suspicious ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {
        "reason": reason
    }

    print("Sending mark request...")
    url = f"https://127.0.0.1:5001/employee/transaction/{transaction_id}/mark_suspicious"
    resp = requests.post(url, headers=headers, json=payload, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        print("Transaction marked as suspicious!")
        return True
    else:
        print(f"Marking transaction failed: {resp.text}")
        return False


def freeze_account(token: str, account_id: int, reason: str):
    """Freeze account"""
    print(f"\n=== Freeze account {account_id} ===")

    headers = {
        "Authorization": f"Bearer {token}"
    }

    payload = {
        "reason": reason
    }

    print("Sending freeze request...")
    url = f"https://127.0.0.1:5001/employee/account/{account_id}/freeze"
    resp = requests.post(url, headers=headers, json=payload, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        print("Account frozen!")
        return True
    else:
        print(f"Freezing account failed: {resp.text}")
        return False


def employee_send_message(token: str, email: str, client_id: int, message_text: str):
    """Employee sends encrypted message to customer"""
    print(f"\n=== Send encrypted message to customer {client_id} ===")

    # 1. Construct signature message
    timestamp = int(time.time())
    message_str = f"send_message|email={email}|to={client_id}|content={message_text}|timestamp={timestamp}"

    # 2. Read private key and HMAC key
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    try:
        with open(f"employee_secret/{safe_email}_private_key.pem", "rb") as private_file:
            private_key_pem = private_file.read()

        # Employee might not have HMAC key file, if not found, generate a temporary one
        try:
            with open(f"employee_secret/{safe_email}_hmac_key.txt", "rb") as hmac_file:
                hmac_key = hmac_file.read()
        except FileNotFoundError:
            hmac_key = os.urandom(32)  # Generate temporary HMAC key
    except FileNotFoundError as e:
        print(f"Error: Key file not found - {str(e)}")
        return None

    # 3. Generate signature and HMAC
    signature_bytes = sign_data(message_str.encode('utf-8'), private_key_pem)
    signature_hex = signature_bytes.hex()
    hmac_value = compute_hmac_sha256(message_str.encode('utf-8'), hmac_key)

    # 4. Construct request payload
    payload = {
        "message": message_str,
        "signature": signature_hex,
        "hmac": hmac_value
    }

    # 5. Send request
    headers = {
        "Authorization": f"Bearer {token}"
    }

    print("Sending encrypted message...")
    url = "https://127.0.0.1:5001/employee/message/send"
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    print(f"Server response: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        message_id = data.get("message_id")
        print(f"Message sent successfully! Message ID: {message_id}")
        return message_id
    else:
        print(f"Message sending failed: {resp.text}")
        return None


if __name__ == "__main__":
    print("==================== Welcome to MyBank Employee Client ====================")

    # Ensure key directory exists
    ensure_directory("employee_secret")

    # Login
    email = input("Enter employee email: ")
    password = getpass.getpass("Enter password: ")

    token = employee_login(email, password)

    if token:
        # Login successful, display function menu
        while True:
            print("\n--- Employee Function Menu ---")
            print("1. Customer Management")
            print("2. Account Operations")
            print("3. Transaction Monitoring")
            print("4. Security Management")
            print("5. Communication")
            print("0. Logout")

            main_choice = input("Enter option: ")

            if main_choice == "1":
                # Customer Management
                print("\nCustomer Management:")
                print("1. Search Customer")
                print("2. View Customer Accounts")
                print("3. Update Customer Information")
                print("0. Return")

                sub_choice = input("Enter option: ")

                if sub_choice == "1":
                    # Search Customer
                    customer_email = input("Enter customer email: ")
                    search_customer(token, customer_email)

                elif sub_choice == "2":
                    # View Customer Accounts
                    customer_id = int(input("Enter customer ID: "))
                    view_customer_accounts(token, customer_id)

                elif sub_choice == "3":
                    # Update Customer Information
                    customer_id = int(input("Enter customer ID: "))
                    new_phone = input("Enter new phone (leave empty to keep unchanged): ")
                    new_address = input("Enter new address (leave empty to keep unchanged): ")

                    phone = new_phone if new_phone else None
                    address = new_address if new_address else None

                    update_customer_info(token, customer_id, phone, address)

            elif main_choice == "2":
                # Account Operations
                print("\nAccount Operations:")
                print("1. View Account Transactions")
                print("2. Transfer on Behalf of Customer")
                print("0. Return")

                sub_choice = input("Enter option: ")

                if sub_choice == "1":
                    # View Account Transactions
                    account_id = int(input("Enter account ID: "))
                    view_account_transactions(token, account_id)

                elif sub_choice == "2":
                    # Transfer on Behalf of Customer
                    source_id = int(input("Enter source account ID: "))
                    dest_id = int(input("Enter destination account ID: "))
                    amount = float(input("Enter amount: "))
                    note = input("Enter note (optional): ") or "Employee Transfer"
                    employee_transfer(token, source_id, dest_id, amount, note)

            elif main_choice == "3":
                # Transaction Monitoring
                print("\nTransaction Monitoring:")
                print("1. Mark Suspicious Transaction")
                print("2. Freeze Account")
                print("0. Return")

                sub_choice = input("Enter option: ")

                if sub_choice == "1":
                    # Mark Suspicious Transaction
                    tx_id = int(input("Enter transaction ID: "))
                    reason = input("Enter reason for marking: ")
                    mark_suspicious_transaction(token, tx_id, reason)

                elif sub_choice == "2":
                    # Freeze Account
                    account_id = int(input("Enter account ID: "))
                    reason = input("Enter reason for freezing: ")
                    freeze_account(token, account_id, reason)

            elif main_choice == "4":
                # Security Management
                print("\nSecurity Management functions not yet implemented")

            elif main_choice == "5":
                # Communication
                print("\nCommunication:")
                print("1. Send Encrypted Message to Customer")
                print("0. Return")

                sub_choice = input("Enter option: ")

                if sub_choice == "1":
                    # Send Encrypted Message to Customer
                    client_id = int(input("Enter customer ID: "))
                    message = input("Enter message content: ")
                    employee_send_message(token, email, client_id, message)

            elif main_choice == "0":
                # Logout
                if employee_logout(token):
                    break
            else:
                print("Invalid option, please try again")
    else:
        print("Login failed, program exiting")