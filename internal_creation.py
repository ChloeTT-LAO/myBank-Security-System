import base64
import requests
from security.encryption import generate_rsa_keypair, serialize_private_key_to_pem, serialize_public_key_to_pem




if __name__ == "__main__":
    name = "Employee"
    password = "employee"
    email = "employee@gmail.com"
    role = "bank_employee"
    phone = "987654321"
    address = "employee road"
    employee_register(name, email, password, phone, address, role)