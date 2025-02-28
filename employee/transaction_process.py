from config.config import DATABASE_URI
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
import datetime
from config.mybank_db import Accounts, Transactions
from security.encryption import aes_256_gcm_encrypt
from security.key_management import retrieve_key_from_db
from security.integrity import generate_transaction_hash
from security.audit import log_operation

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
key_name = "user_transaction"


def deposit_to_customer(employee_user, account_id, amount, note="Employee Deposit"):
    """
    员工代表客户进行存款操作
    """
    session = Session()
    try:
        account = session.query(Accounts).filter_by(account_id=account_id).first()
        if not account:
            raise Exception("Account not found.")

        # 检查账户是否被冻结
        if getattr(account, 'is_frozen', False):
            raise Exception("Account is frozen and cannot accept deposits.")

        # 执行存款
        account.balance += amount

        # 加密交易备注
        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        note_nonce, encrypted_note = aes_256_gcm_encrypt(note.encode('utf-8'), aes_key)

        # 创建交易数据，用于完整性校验
        current_time = datetime.datetime.now(tz=datetime.timezone.utc)
        transaction_data = {
            "source_account_id": None,
            "destination_account_id": account_id,
            "amount": amount,
            "transaction_type": 'deposit',
            "timestamp": current_time,
            "details": encrypted_note
        }

        # 计算完整性校验和
        integrity_checksum = generate_transaction_hash(transaction_data)

        # 记录交易
        transaction = Transactions(
            source_account_id=None,  # 存款可能没有source
            destination_account_id=account_id,
            amount=amount,
            transaction_type='deposit',
            status='completed',
            timestamp=current_time,
            encrypted_note=encrypted_note,
            note_nonce=note_nonce,
            key_version=key_version,
            key_name=key_name,
            integrity_checksum=integrity_checksum,
            processed_by_employee=employee_user.user_id
        )
        session.add(transaction)
        session.commit()

        # 记录操作
        log_operation(
            employee_user.user_id,
            "employee_deposit",
            f"Deposited {amount} to account {account_id}"
        )

        return transaction
    except:
        session.rollback()
        raise
    finally:
        session.close()


def withdraw_from_customer(employee_user, account_id, amount, note="Employee Withdrawal"):
    """
    员工代表客户进行取款操作
    """
    session = Session()
    try:
        account = session.query(Accounts).filter_by(account_id=account_id).first()
        if not account:
            raise Exception("Account not found.")

        # 检查账户是否被冻结
        if getattr(account, 'is_frozen', False):
            raise Exception("Account is frozen and cannot process withdrawals.")

        if account.balance < amount:
            raise Exception("Insufficient funds.")

        # 执行取款
        account.balance -= amount

        # 加密交易备注
        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        note_nonce, encrypted_note = aes_256_gcm_encrypt(note.encode('utf-8'), aes_key)

        # 创建交易数据，用于完整性校验
        current_time = datetime.datetime.now(tz=datetime.timezone.utc)
        transaction_data = {
            "source_account_id": account_id,
            "destination_account_id": None,
            "amount": amount,
            "transaction_type": 'withdrawal',
            "timestamp": current_time,
            "details": encrypted_note
        }

        # 计算完整性校验和
        integrity_checksum = generate_transaction_hash(transaction_data)

        # 记录交易
        transaction = Transactions(
            source_account_id=account_id,
            destination_account_id=None,
            amount=amount,
            transaction_type='withdrawal',
            status='completed',
            timestamp=current_time,
            encrypted_note=encrypted_note,
            note_nonce=note_nonce,
            key_version=key_version,
            key_name=key_name,
            integrity_checksum=integrity_checksum,
            processed_by_employee=employee_user.user_id
        )
        session.add(transaction)
        session.commit()

        # 记录操作
        log_operation(
            employee_user.user_id,
            "employee_withdrawal",
            f"Withdrew {amount} from account {account_id}"
        )

        return transaction
    except:
        session.rollback()
        raise
    finally:
        session.close()


def employee_transfer(employee_user, source_account_id, destination_account_id, amount, note="Employee Transfer"):
    """
    员工代客户进行转账操作
    """
    session = Session()
    try:
        source_account = session.query(Accounts).filter_by(account_id=source_account_id).first()
        destination_account = session.query(Accounts).filter_by(account_id=destination_account_id).first()

        if not source_account or not destination_account:
            raise Exception("Source or destination account not found.")

        # 检查账户是否被冻结
        if getattr(source_account, 'is_frozen', False):
            raise Exception("Source account is frozen and cannot process transfers.")

        if getattr(destination_account, 'is_frozen', False):
            raise Exception("Destination account is frozen and cannot receive transfers.")

        if source_account.balance < amount:
            raise Exception("Insufficient funds in source account.")

        # 执行转账
        source_account.balance -= amount
        destination_account.balance += amount

        # 加密交易备注
        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        note_nonce, encrypted_note = aes_256_gcm_encrypt(note.encode('utf-8'), aes_key)

        # 创建交易数据，用于完整性校验
        current_time = datetime.datetime.now(tz=datetime.timezone.utc)
        transaction_data = {
            "source_account_id": source_account_id,
            "destination_account_id": destination_account_id,
            "amount": amount,
            "transaction_type": 'transfer',
            "timestamp": current_time,
            "details": encrypted_note
        }

        # 计算完整性校验和
        integrity_checksum = generate_transaction_hash(transaction_data)

        # 记录交易
        transaction = Transactions(
            source_account_id=source_account_id,
            destination_account_id=destination_account_id,
            amount=amount,
            transaction_type='transfer',
            status='completed',
            timestamp=current_time,
            encrypted_note=encrypted_note,
            note_nonce=note_nonce,
            key_version=key_version,
            key_name=key_name,
            integrity_checksum=integrity_checksum,
            processed_by_employee=employee_user.user_id
        )
        session.add(transaction)
        session.commit()

        # 记录操作
        log_operation(
            employee_user.user_id,
            "employee_transfer",
            f"Transferred {amount} from account {source_account_id} to account {destination_account_id}"
        )

        return transaction
    except:
        session.rollback()
        raise
    finally:
        session.close()