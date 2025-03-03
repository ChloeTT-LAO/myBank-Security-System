import hashlib
from decimal import Decimal
from typing import Union, Tuple, Dict, Any, Optional
from config.mybank_db import Accounts, Transactions
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
import datetime

from security.behavioral_authentication import update_transaction_behavior, should_require_verification
from security.blockchain import record_transaction
from security.encryption import aes_256_gcm_encrypt
from security.key_management import retrieve_key_from_db
from security.integrity import generate_transaction_hash, generate_transaction_signature, is_high_risk_transaction
from security.audit import log_operation

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
key_name = "user_transaction"


def transfer(source_account_number: str, destination_account_number: str, amount: Union[str, float, Decimal],
             note: str = "Transfer", user_id: int = None, hmac_key: bytes = None, verification_code: str = None):
    """
    Client-side transfer function to support high-value transaction verification
    Return the transaction ID and balance, or information that requires additional verification
    """
    session = Session()
    try:
        # Convert the amount to Decimal
        if isinstance(amount, str):
            amount = Decimal(amount)
        elif isinstance(amount, float):
            amount = Decimal(str(amount))

        # Find source and destination accounts
        source_account = session.query(Accounts).filter_by(
            account_number_hash=hashlib.sha256(source_account_number.encode('utf-8')).hexdigest()).first()
        destination_account = session.query(Accounts).filter_by(
            account_number_hash=hashlib.sha256(destination_account_number.encode('utf-8')).hexdigest()).first()

        if not source_account or not destination_account:
            raise Exception("Source or destination account not found.")

        if source_account.balance < amount:
            raise Exception("Insufficient funds.")

        # Create a transaction data dictionary for risk assessment and integrity check
        current_time = datetime.datetime.now(tz=datetime.timezone.utc)
        transaction_data = {
            "source_account_id": source_account.account_id,
            "destination_account_id": destination_account.account_id,
            "amount": amount,
            "transaction_type": 'transfer',
            "timestamp": current_time.isoformat(),
            "details": note
        }

        if user_id:
            update_transaction_behavior(user_id, transaction_data)

        # Determine whether additional verification is required based on behavioral risk and transaction characteristics
        requires_verification = False
        if user_id:
            requires_verification = should_require_verification(user_id, transaction_data)
        else:
            # If there is no user ID, fall back to the basic high risk transaction judgment
            requires_verification = is_high_risk_transaction(transaction_data)

        # If verification is required but no verification code is provided
        if requires_verification and not verification_code:
            return {
                "status": "additional_verification_required",
                "message": "This transaction requires additional verification.",
                "transaction_data": transaction_data,
                "reason": "Risk assessment" if user_id else "High value transaction"
            }

        # Check if additional validation is required
        if is_high_risk_transaction(transaction_data) and not verification_code:
            # Returns information that requires additional validation
            return {
                "status": "additional_verification_required",
                "message": "This high-value transaction requires additional verification.",
                "transaction_data": transaction_data
            }

        # There is a verification code, but it is not a high-risk transaction and does not require verification
        # If it is a high-risk transaction and has a verification code, it will be verified later

        # Execute a transfer
        source_account.balance -= amount
        destination_account.balance += amount
        balance = source_account.balance

        # Crypto Trading Notes
        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        note_nonce, encrypted_note = aes_256_gcm_encrypt(note.encode('utf-8'), aes_key)

        # Update the details in the transaction data to the encrypted content for integrity check
        transaction_data["details"] = encrypted_note
        transaction_data["timestamp"] = current_time

        # Calculate the transaction integrity checksum
        integrity_checksum = generate_transaction_hash(transaction_data)

        # Generate transaction signatures (if HMAC keys are provided)
        transaction_signature = None
        if hmac_key:
            transaction_signature = generate_transaction_signature(transaction_data, hmac_key)

        # Determine whether validation and validation status is required
        requires_verification = is_high_risk_transaction(transaction_data)
        verification_status = 'not_required'
        if requires_verification:
            verification_status = 'pending'  # The default is waiting for verification

        # Create a transaction record
        transaction = Transactions(
            source_account_id=source_account.account_id,
            destination_account_id=destination_account.account_id,
            amount=amount,
            transaction_type='transfer',
            status='pending',  # The initial state is waiting
            timestamp=current_time,
            encrypted_note=encrypted_note,
            note_nonce=note_nonce,
            key_version=key_version,
            key_name=key_name,
            integrity_checksum=integrity_checksum,
            transaction_signature=transaction_signature,
            requires_additional_verification=requires_verification,
            verification_status=verification_status
        )
        print(f"integrity_checksum: {transaction.integrity_checksum}")
        print(f"transaction_signature: {transaction.transaction_signature}")

        session.add(transaction)
        session.commit()

        # If it is a high-risk transaction and a captCHA is provided, verify it
        if requires_verification and verification_code and user_id:
            from security.integrity import verify_high_value_transaction
            verification_success = verify_high_value_transaction(transaction.transaction_id, user_id, verification_code)

            # Update trading status
            transaction = session.query(Transactions).get(transaction.transaction_id)
            if verification_success:
                transaction.status = 'completed'
                transaction.verification_status = 'verified'
            else:
                transaction.status = 'rejected'
                transaction.verification_status = 'failed'
                # Rollback transfer
                source_account.balance += amount
                destination_account.balance -= amount
                balance = source_account.balance

            session.commit()

            if not verification_success:
                raise Exception("Transaction verification failed. The transaction has been rejected.")
        elif not requires_verification:
            # If no verification is required, complete the transaction directly
            transaction.status = 'completed'
            session.commit()

        # record operation
        if user_id:
            log_operation(
                user_id,
                "fund_transfer",
                f"Transferred {amount} from account {source_account.account_id} to {destination_account.account_id}"
            )

        if transaction.status == 'completed':
            try:
                blockchain_result = record_transaction(transaction.transaction_id, user_id)
                print(f"Transaction recorded to blockchain: {blockchain_result}")
            except Exception as e:
                print(f"Error recording transaction to blockchain: {str(e)}")

        return transaction.transaction_id, balance

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def deposit(account_number: str, amount: Union[str, float, Decimal], note: str = "Deposit",
            user_id: int = None, hmac_key: bytes = None) -> Tuple[int, Decimal]:
    """
    存款函数
    """
    session = Session()
    try:
        # 将amount转换为Decimal
        if isinstance(amount, str):
            amount = Decimal(amount)
        elif isinstance(amount, float):
            amount = Decimal(str(amount))

        # 查找账户
        account = session.query(Accounts).filter_by(
            account_number_hash=hashlib.sha256(account_number.encode('utf-8')).hexdigest()).first()

        if not account:
            raise Exception("Account not found.")

        # 执行存款
        account.balance += amount
        balance = account.balance

        # 加密交易备注
        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        note_nonce, encrypted_note = aes_256_gcm_encrypt(note.encode('utf-8'), aes_key)

        # 创建交易数据，用于完整性校验
        current_time = datetime.datetime.now(tz=datetime.timezone.utc)
        transaction_data = {
            "source_account_id": None,
            "destination_account_id": account.account_id,
            "amount": amount,
            "transaction_type": 'deposit',
            "timestamp": current_time,
            "details": encrypted_note
        }

        # 计算完整性校验和
        integrity_checksum = generate_transaction_hash(transaction_data)

        # 生成交易签名（如果提供了HMAC密钥）
        transaction_signature = None
        if hmac_key:
            transaction_signature = generate_transaction_signature(transaction_data, hmac_key)

        # 创建交易记录
        transaction = Transactions(
            source_account_id=None,  # 存款没有源账户
            destination_account_id=account.account_id,
            amount=amount,
            transaction_type='deposit',
            status='completed',
            timestamp=current_time,
            encrypted_note=encrypted_note,
            note_nonce=note_nonce,
            key_version=key_version,
            key_name=key_name,
            integrity_checksum=integrity_checksum,
            transaction_signature=transaction_signature
        )

        session.add(transaction)
        session.commit()

        # 记录操作
        if user_id:
            log_operation(
                user_id,
                "deposit",
                f"Deposited {amount} to account {account.account_id}"
            )

        return transaction.transaction_id, balance

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def withdraw(account_number: str, amount: Union[str, float, Decimal], note: str = "Withdrawal",
             user_id: int = None, hmac_key: bytes = None) -> Tuple[int, Decimal]:
    """
    取款函数
    """
    session = Session()
    try:
        # 将amount转换为Decimal
        if isinstance(amount, str):
            amount = Decimal(amount)
        elif isinstance(amount, float):
            amount = Decimal(str(amount))

        # 查找账户
        account = session.query(Accounts).filter_by(
            account_number_hash=hashlib.sha256(account_number.encode('utf-8')).hexdigest()).first()

        if not account:
            raise Exception("Account not found.")

        if account.balance < amount:
            raise Exception("Insufficient funds.")

        # 执行取款
        account.balance -= amount
        balance = account.balance

        # 加密交易备注
        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        note_nonce, encrypted_note = aes_256_gcm_encrypt(note.encode('utf-8'), aes_key)

        # 创建交易数据，用于完整性校验
        current_time = datetime.datetime.now(tz=datetime.timezone.utc)
        transaction_data = {
            "source_account_id": account.account_id,
            "destination_account_id": None,
            "amount": amount,
            "transaction_type": 'withdraw',
            "timestamp": current_time,
            "details": encrypted_note
        }

        # 计算完整性校验和
        integrity_checksum = generate_transaction_hash(transaction_data)

        # 生成交易签名（如果提供了HMAC密钥）
        transaction_signature = None
        if hmac_key:
            transaction_signature = generate_transaction_signature(transaction_data, hmac_key)

        # 创建交易记录
        transaction = Transactions(
            source_account_id=account.account_id,
            destination_account_id=None,  # 取款没有目标账户
            amount=amount,
            transaction_type='withdraw',
            status='completed',
            timestamp=current_time,
            encrypted_note=encrypted_note,
            note_nonce=note_nonce,
            key_version=key_version,
            key_name=key_name,
            integrity_checksum=integrity_checksum,
            transaction_signature=transaction_signature
        )

        session.add(transaction)
        session.commit()

        # 记录操作
        if user_id:
            log_operation(
                user_id,
                "withdrawal",
                f"Withdrew {amount} from account {account.account_id}"
            )

        return transaction.transaction_id, balance

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()