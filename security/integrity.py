import base64
import hashlib
import json
import hmac
import pyotp
from decimal import Decimal
from typing import Dict, Any, Optional
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.mybank_db import Transactions, Users, SecurityLogs
from config.config import DATABASE_URI
from security.encryption import compute_hmac_sha256
import datetime

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

# Define high-risk transaction thresholds
HIGH_VALUE_THRESHOLD = Decimal('10000.00')  # High-value transaction threshold
UNUSUAL_TRANSACTION_TYPES = ["international_transfer", "crypto_exchange"]


def generate_transaction_hash(transaction_data: Dict[str, Any]) -> str:
    """
    Generate a hash for transaction integrity verification
    """
    canonical_data = {
        "source_account_id": transaction_data.get("source_account_id"),
        "destination_account_id": transaction_data.get("destination_account_id"),
        "amount": str(transaction_data.get("amount")),
        "transaction_type": transaction_data.get("transaction_type"),
        "timestamp": transaction_data.get("timestamp").isoformat() if isinstance(transaction_data.get("timestamp"),
                                                                                 datetime.datetime) else transaction_data.get(
            "timestamp"),
        "details": base64.b64encode(transaction_data.get("details", "")).decode('utf-8')
    }

    canonical_json = json.dumps(canonical_data, sort_keys=True)

    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()


def verify_transaction_integrity(transaction_id: int) -> bool:
    """
    Verify the integrity of transaction records
    """
    session = Session()
    try:
        transaction = session.query(Transactions).filter_by(transaction_id=transaction_id).first()
        if not transaction:
            return False

        # Only transactions with integrity checksums can be verified
        if not transaction.integrity_checksum:
            return False

        # Create transaction data dictionary from transaction record
        transaction_data = {
            "source_account_id": transaction.source_account_id,
            "destination_account_id": transaction.destination_account_id,
            "amount": transaction.amount,
            "transaction_type": transaction.transaction_type,
            "timestamp": transaction.timestamp,
            "details": transaction.encrypted_note  # Note that encrypted details are used here
        }

        # Generate hash of current data
        current_hash = generate_transaction_hash(transaction_data)

        # Compare with stored hash value
        return current_hash == transaction.integrity_checksum
    finally:
        session.close()


def generate_transaction_signature(transaction_data: Dict[str, Any], hmac_key: bytes) -> str:
    """
    Generate digital signature for transactions using HMAC
    """
    # Create normalized representation of transaction data
    canonical_data = {
        "source_account_id": transaction_data.get("source_account_id"),
        "destination_account_id": transaction_data.get("destination_account_id"),
        "amount": str(transaction_data.get("amount")),
        "transaction_type": transaction_data.get("transaction_type"),
        "timestamp": transaction_data.get("timestamp").isoformat() if isinstance(transaction_data.get("timestamp"),
                                                                                 datetime.datetime) else transaction_data.get(
            "timestamp"),
        "details": base64.b64encode(transaction_data.get("details", "")).decode('utf-8')
    }

    # Convert data to JSON string
    canonical_json = json.dumps(canonical_data, sort_keys=True)

    # Calculate HMAC
    return compute_hmac_sha256(canonical_json.encode('utf-8'), hmac_key)


def verify_transaction_signature(transaction_data: Dict[str, Any], signature: str, hmac_key: bytes) -> bool:
    """
    Verify transaction signature
    """
    expected_signature = generate_transaction_signature(transaction_data, hmac_key)
    return hmac.compare_digest(expected_signature, signature)


def is_high_risk_transaction(transaction_data: Dict[str, Any]) -> bool:
    """
    Check if a transaction is high-risk
    """
    # Check if transaction amount exceeds threshold
    amount = transaction_data.get("amount", 0)
    if isinstance(amount, str):
        amount = Decimal(amount)

    if amount >= HIGH_VALUE_THRESHOLD:
        return True

    # Check if transaction type is unusual
    if transaction_data.get("transaction_type") in UNUSUAL_TRANSACTION_TYPES:
        return True

    # Can add more risk checking logic, such as cross-border transactions, large transactions from new accounts, etc.

    return False


def require_additional_verification(transaction_data: Dict[str, Any]) -> bool:
    """
    Determine if a transaction requires additional verification
    """
    # High-risk transactions need additional verification
    if is_high_risk_transaction(transaction_data):
        return True

    # Other situations that may require verification
    # For example, transactions from unusual locations, abnormal transaction patterns, etc.

    return False


def verify_high_value_transaction(transaction_id: Optional[int], user_id: int, verification_code: str) -> bool:
    """
    Complete additional verification for high-value transactions
    If transaction_id is None, only verify the code without binding to a specific transaction
    """
    session = Session()
    try:
        # Verify if it's a valid transaction (if transaction ID is provided)
        if transaction_id is not None:
            transaction = session.query(Transactions).filter_by(transaction_id=transaction_id).first()
            if not transaction:
                return False

        # Get user TOTP secret
        user = session.query(Users).filter_by(user_id=user_id).first()
        if not user:
            return False

        # Use TOTP for additional verification
        totp = pyotp.TOTP(user.totp_secret)
        current_totp = totp.now()
        print(f"Current TOTP code: {current_totp}")
        verification_code = input("Please enter the verification code in your authenticator application: ")

        verification_result = totp.verify(verification_code)

        # If there's a transaction ID, record the verification result
        if transaction_id is not None:
            # Update transaction verification status
            transaction = session.query(Transactions).filter_by(transaction_id=transaction_id).first()
            if transaction:
                transaction.verification_status = 'verified' if verification_result else 'failed'
                session.commit()

            # Record verification event
            security_log = SecurityLogs(
                user_id=user_id,
                event_type="high_value_transaction_verification",
                description=f"High value transaction {transaction_id} verification {'success' if verification_result else 'failed'}",
                created_at=datetime.datetime.now(tz=datetime.timezone.utc)
            )
            session.add(security_log)
            session.commit()

        return verification_result
    except Exception as e:
        session.rollback()
        print(f"Error in high value transaction verification: {str(e)}")
        return False
    finally:
        session.close()