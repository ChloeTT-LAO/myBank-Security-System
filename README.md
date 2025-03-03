# MyBank Secure Online Banking System

This README provides instructions for setting up and testing the MyBank secure online banking system as demonstrated in the report.

## System Overview

The MyBank online banking system is a comprehensive financial platform with robust security features including:
- AES-256-GCM data encryption
- RSA-2048 asymmetric cryptography
- Multi-factor authentication (password + TOTP)
- WebAuthn/FIDO2 support
- HMAC message integrity verification
- Blockchain transaction verification
- Secure key management with backup and rotation

## Setup Instructions

### Prerequisites

- Python 3.8 or higher
- PostgreSQL database
- Required Python packages (listed in requirements.txt)

### Installation Steps

1. Clone the repository:
   ```
   git clone https://github.com/username/mybank-system.git
   cd mybank-system
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

### Database Setup Options

#### Option 1: Using the provided database backup (Recommended for testing)

1. The submission includes a pre-configured PostgreSQL database backup file: `mybank_db_backup.sql`
2. To restore the database:
   ```
   createdb mybank_db
   psql mybank_db < mybank_db_backup.sql
   ```
3. This database includes all the necessary tables and test data mentioned in the report

#### Option 2: Setting up a new database

1. Create a database named "mybank_db"
   ```
   createdb mybank_db
   ```
2. Update the database connection string in `config/config.py` if needed
3. Initialize the database schema:
   ```
   python config/db_connection.py
   ```
4. Generate initial keys:
   ```
   python system_admin/key_management.py
   ```

6. Start the server:
   ```
   python app.py
   ```

## Testing the System

### 1. Client Registration and Authentication

#### 1.1 User Registration
1. Run the client demo script:
   ```
   python client/client_demo.py
   ```
2. Select option "1" to register a new user
3. Enter test user information as shown in the report (e.g., name, email, password)
4. The system will generate RSA keys, TOTP keys, and HMAC keys
5. You should see a confirmation message and the TOTP URI

#### 1.2 User Login
1. In the client demo, select option "2" to log in
2. Enter the email and password you registered with
3. When prompted, enter the TOTP code from Run interface
4. You should see a "Login successful" message and receive a token

#### 1.3 WebAuthn Registration and Login (Optional)
1. After logging in, select option "10" from the user function menu
2. Follow the prompts to register a WebAuthn credential
3. Log out and then log back in using WebAuthn by selecting option "2" for login method

### 2. Account Management and Transactions

#### 2.1 Create Account
1. While logged in, select option "1" from the user function menu
2. Enter the account type (e.g., "savings" or "checking")
3. The system will create a new account and return the account number

#### 2.2 Make Deposits and Withdrawals
1. Select option "2" to make a deposit
   - Enter the account number and amount
2. Select option "3" to make a withdrawal
   - Enter the account number and amount

#### 2.3 Fund Transfers
1. Select option "4" to make a transfer
2. Enter the source account, destination account, and amount
3. For high-value transfers (>10000), you'll be prompted for additional TOTP verification

### 3. Security Feature Testing

#### 3.1 Key Management (System Administrator)
1. Run the admin demo script:
   ```
   python system_admin/admin_demo.py
   ```
2. Login as an admin user (email: admin1@mybank.com, password: AdminPwd123!)
3. Select option "3" for key management
4. Test key generation, rotation, backup, and restore functions

#### 3.2 Data Encryption Verification
1. Use the database client to view the `users` and `accounts` tables
2. Verify that sensitive fields like names, phone numbers, and addresses are stored in encrypted form

#### 3.3 Communication Security
1. Use a tool like Wireshark to capture HTTPS traffic
2. Verify that all communications are encrypted via TLS
3. Observe in the client code that all requests include digital signatures

#### 3.4 Integrity Verification
1. Make a transaction and note the transaction ID
2. As an admin, use the blockchain verification option to verify the transaction integrity
3. Try modifying transaction data directly in the database to see integrity check failures


## Troubleshooting

- **Database Connection Issues**: 
  - Check the connection string in `config/config.py`
  - If using the provided database backup, ensure the PostgreSQL user has proper permissions
  - Default connection string is: `postgresql+psycopg2://postgres:011017@localhost:5432/mybank_db`
- **Key Management Errors**: Verify file permissions for key storage directories


## Additional Resources

For further details about the system design and implementation, please refer to the full technical report document.
