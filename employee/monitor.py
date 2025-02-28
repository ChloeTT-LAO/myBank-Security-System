from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
from config.mybank_db import Transactions, Accounts, SecurityLogs
import datetime
from security.audit import log_operation, log_security_event

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def mark_suspicious_transaction(employee_user, transaction_id, reason="Suspicious activity detected"):
    """
    员工标记可疑交易
    """
    session = Session()
    try:
        transaction = session.query(Transactions).filter_by(transaction_id=transaction_id).first()
        if not transaction:
            raise Exception("Transaction not found.")

        # 标记交易为可疑
        transaction.is_suspicious = True
        transaction.suspicious_reason = reason

        # 如果交易还未完成，拒绝交易
        if transaction.status == 'pending':
            transaction.status = 'rejected'

            # 如果是转账交易且有源账户和目标账户，回滚交易金额
            if (transaction.transaction_type == 'transfer' and
                    transaction.source_account_id and
                    transaction.destination_account_id):

                source_account = session.query(Accounts).filter_by(account_id=transaction.source_account_id).first()
                destination_account = session.query(Accounts).filter_by(
                    account_id=transaction.destination_account_id).first()

                if source_account and destination_account:
                    source_account.balance += transaction.amount
                    destination_account.balance -= transaction.amount

        session.commit()

        # 记录安全事件
        log_security_event(
            employee_user.user_id,
            "transaction_marked_suspicious",
            f"Transaction {transaction_id} marked as suspicious: {reason}"
        )

        return transaction
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def freeze_customer_account(employee_user, account_id, reason="Security concern"):
    """
    员工冻结客户账户
    """
    session = Session()
    try:
        account = session.query(Accounts).filter_by(account_id=account_id).first()
        if not account:
            raise Exception("Account not found.")

        # 检查账户是否已经被冻结
        if getattr(account, 'is_frozen', False):
            raise Exception("Account is already frozen.")

        # 冻结账户
        account.is_frozen = True
        account.freeze_reason = reason
        account.frozen_at = datetime.datetime.now(tz=datetime.timezone.utc)
        account.frozen_by = employee_user.user_id

        session.commit()

        # 记录安全事件
        log_security_event(
            employee_user.user_id,
            "account_frozen",
            f"Account {account_id} frozen: {reason}"
        )

        # 记录操作
        log_operation(
            employee_user.user_id,
            "freeze_account",
            f"Froze account {account_id}: {reason}"
        )

        return account
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def unfreeze_customer_account(employee_user, account_id, reason="Security verification completed"):
    """
    员工解冻客户账户
    """
    session = Session()
    try:
        account = session.query(Accounts).filter_by(account_id=account_id).first()
        if not account:
            raise Exception("Account not found.")

        # 检查账户是否已经被冻结
        if not getattr(account, 'is_frozen', False):
            raise Exception("Account is not frozen.")

        # 解冻账户
        account.is_frozen = False
        account.unfreeze_reason = reason
        account.unfrozen_at = datetime.datetime.now(tz=datetime.timezone.utc)
        account.unfrozen_by = employee_user.user_id

        session.commit()

        # 记录安全事件
        log_security_event(
            employee_user.user_id,
            "account_unfrozen",
            f"Account {account_id} unfrozen: {reason}"
        )

        # 记录操作
        log_operation(
            employee_user.user_id,
            "unfreeze_account",
            f"Unfroze account {account_id}: {reason}"
        )

        return account
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_suspicious_transactions(employee_user, limit=50, offset=0):
    """
    获取所有被标记为可疑的交易
    """
    session = Session()
    try:
        transactions = session.query(Transactions) \
            .filter_by(is_suspicious=True) \
            .order_by(Transactions.timestamp.desc()) \
            .limit(limit).offset(offset).all()

        result = []
        for tx in transactions:
            result.append({
                'transaction_id': tx.transaction_id,
                'source_account_id': tx.source_account_id,
                'destination_account_id': tx.destination_account_id,
                'amount': float(tx.amount),
                'transaction_type': tx.transaction_type,
                'status': tx.status,
                'timestamp': tx.timestamp.isoformat(),
                'suspicious_reason': tx.suspicious_reason
            })

        # 记录操作
        log_operation(
            employee_user.user_id,
            "view_suspicious_transactions",
            f"Viewed {len(result)} suspicious transactions"
        )

        return result
    finally:
        session.close()