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
             note: str = "Transfer", user_id: int = None, hmac_key: bytes = None, verification_code: str = None) -> \
Union[Tuple[int, Decimal], Dict[str, Any]]:
    """
    客户端转账函数，支持高价值交易验证
    返回交易ID和余额，或者需要额外验证的信息
    """
    session = Session()
    try:
        # 将amount转换为Decimal
        if isinstance(amount, str):
            amount = Decimal(amount)
        elif isinstance(amount, float):
            amount = Decimal(str(amount))

        # 查找源账户和目标账户
        source_account = session.query(Accounts).filter_by(
            account_number_hash=hashlib.sha256(source_account_number.encode('utf-8')).hexdigest()).first()
        destination_account = session.query(Accounts).filter_by(
            account_number_hash=hashlib.sha256(destination_account_number.encode('utf-8')).hexdigest()).first()

        if not source_account or not destination_account:
            raise Exception("Source or destination account not found.")

        if source_account.balance < amount:
            raise Exception("Insufficient funds.")

        # 创建交易数据字典，用于风险评估和完整性校验
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

            # 基于行为风险和交易特征决定是否需要额外验证
        requires_verification = False
        if user_id:
            requires_verification = should_require_verification(user_id, transaction_data)
        else:
            # 如果没有用户ID，回退到基本的高风险交易判断
            requires_verification = is_high_risk_transaction(transaction_data)

        # 如果需要验证但没有提供验证码
        if requires_verification and not verification_code:
            return {
                "status": "additional_verification_required",
                "message": "This transaction requires additional verification.",
                "transaction_data": transaction_data,
                "reason": "Risk assessment" if user_id else "High value transaction"
            }

        # 检查是否需要额外验证
        if is_high_risk_transaction(transaction_data) and not verification_code:
            # 返回需要额外验证的信息
            return {
                "status": "additional_verification_required",
                "message": "This high-value transaction requires additional verification.",
                "transaction_data": transaction_data
            }

        # 有验证码但不是高风险交易，不需要验证
        # 是高风险交易且有验证码，则在后面会验证

        # 执行转账
        source_account.balance -= amount
        destination_account.balance += amount
        balance = source_account.balance

        # 加密交易备注
        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        note_nonce, encrypted_note = aes_256_gcm_encrypt(note.encode('utf-8'), aes_key)

        # 更新交易数据中的详情为加密后的内容，用于完整性校验
        transaction_data["details"] = encrypted_note
        transaction_data["timestamp"] = current_time

        # 计算交易完整性校验和
        integrity_checksum = generate_transaction_hash(transaction_data)

        # 生成交易签名（如果提供了HMAC密钥）
        transaction_signature = None
        if hmac_key:
            transaction_signature = generate_transaction_signature(transaction_data, hmac_key)

        # 确定是否需要验证和验证状态
        requires_verification = is_high_risk_transaction(transaction_data)
        verification_status = 'not_required'
        if requires_verification:
            verification_status = 'pending'  # 默认为等待验证

        # 创建交易记录
        transaction = Transactions(
            source_account_id=source_account.account_id,
            destination_account_id=destination_account.account_id,
            amount=amount,
            transaction_type='transfer',
            status='pending',  # 初始状态为等待
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

        session.add(transaction)
        session.commit()

        # 如果是高风险交易且提供了验证码，验证它
        if requires_verification and verification_code and user_id:
            from security.integrity import verify_high_value_transaction
            verification_success = verify_high_value_transaction(transaction.transaction_id, user_id, verification_code)

            # 更新交易状态
            transaction = session.query(Transactions).get(transaction.transaction_id)
            if verification_success:
                transaction.status = 'completed'
                transaction.verification_status = 'verified'
            else:
                transaction.status = 'rejected'
                transaction.verification_status = 'failed'
                # 回滚转账
                source_account.balance += amount
                destination_account.balance -= amount
                balance = source_account.balance

            session.commit()

            if not verification_success:
                raise Exception("Transaction verification failed. The transaction has been rejected.")
        elif not requires_verification:
            # 如果不需要验证，直接完成交易
            transaction.status = 'completed'
            session.commit()

        # 记录操作
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