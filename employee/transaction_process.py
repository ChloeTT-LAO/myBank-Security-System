from config.config import DATABASE_URI
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
import datetime
from config.mybank_db import Accounts, Transactions
from client.transfer import transfer

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def deposit_to_customer(employee_user, account_id, amount, note="Deposit"):
    """
    员工代表客户进行存款操作
    """
    session = Session()
    try:
        account = session.query(Accounts).filter_by(account_id=account_id).first()
        if not account:
            raise Exception("Account not found.")

        account.balance += amount

        # 记录交易
        transaction = Transactions(
            source_account_id=None,  # 存款可能没有source
            destination_account_id=account_id,
            amount=amount,
            transaction_type='deposit',
            status='completed',
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            # encrypted_details=encrypt_data(note)  # 如需加密备注
        )
        session.add(transaction)
        session.commit()
        return transaction
    except:
        session.rollback()
        raise
    finally:
        session.close()


def withdraw_from_customer(employee_user, account_id, amount, note="Withdrawal"):
    """
    员工代表客户进行取款操作
    """
    session = Session()
    try:
        account = session.query(Accounts).filter_by(account_id=account_id).first()
        if not account:
            raise Exception("Account not found.")
        if account.balance < amount:
            raise Exception("Insufficient funds.")

        account.balance -= amount

        transaction = Transactions(
            source_account_id=account_id,
            destination_account_id=None,
            amount=amount,
            transaction_type='withdrawal',
            status='completed',
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            # encrypted_details=encrypt_data(note)
        )
        session.add(transaction)
        session.commit()
        return transaction
    except:
        session.rollback()
        raise
    finally:
        session.close()


def employee_transfer(employee_user, source_account_id, destination_account_id, amount, note="Employee Transfer"):
    """
    员工代客户进行转账操作
    使用你已经在 transactions.py 中实现的 transfer_funds 函数
    """
    # 这里直接调用现有的 transfer_funds 函数
    return transfer_funds(source_account_id, destination_account_id, amount, note)

