from config.config import DATABASE_URI
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.mybank_db import Transactions, Accounts

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

def mark_suspicious_transaction(employee_user, transaction_id, reason=""):
    """
    员工可将交易标记为可疑（假设 Transactions 表中有 is_suspicious 字段）
    """
    session = Session()
    try:
        t = session.query(Transactions).filter_by(transaction_id=transaction_id).first()
        if not t:
            raise Exception("Transaction not found.")

        # 你需要在 Transactions 中加一个 is_suspicious 或 suspicious_reason 字段
        # 这里假设我们添加了 suspicious_reason, is_suspicious
        t.is_suspicious = True
        t.suspicious_reason = reason
        session.commit()
        return t
    except:
        session.rollback()
        raise
    finally:
        session.close()

def freeze_customer_account(employee_user, account_id, reason=""):
    """
    员工发现可疑活动时可冻结客户账户 (需在 Accounts 表添加 is_frozen, freeze_reason 字段)
    """
    session = Session()
    try:
        account = session.query(Accounts).filter_by(account_id=account_id).first()
        if not account:
            raise Exception("Account not found.")
        account.is_frozen = True
        account.freeze_reason = reason
        session.commit()
        return account
    except:
        session.rollback()
        raise
    finally:
        session.close()