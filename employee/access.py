from config.config import DATABASE_URI
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.mybank_db import Accounts, Users, Transactions

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def view_customer_accounts(employee_user, customer_id):
    """
    员工查看指定客户的所有账户
    """
    session = Session()
    try:
        # 确保 customer_id 存在且是 client
        customer = session.query(Users).filter_by(user_id=customer_id).first()
        if not customer or customer.role != 'client':
            raise Exception("The specified user is not a valid customer.")

        accounts = session.query(Accounts).filter_by(user_id=customer_id).all()
        result = []
        for acc in accounts:
            result.append({
                'account_id': acc.account_id,
                'account_number': acc.account_number,
                'balance': float(acc.balance),
                'account_type': acc.account_type
            })
        return result
    finally:
        session.close()


def view_customer_transactions(employee_user, account_id):
    """
    员工查看指定账户的交易记录
    """
    session = Session()
    try:
        # 找到账户并确认它属于某个客户
        account = session.query(Accounts).filter_by(account_id=account_id).first()
        if not account:
            raise Exception("Account not found.")

        # 查询与此账户相关的所有交易
        txs = session.query(Transactions).filter(
            (Transactions.source_account_id == account_id) |
            (Transactions.destination_account_id == account_id)
        ).order_by(Transactions.timestamp.desc()).all()

        result = []
        for t in txs:
            # 如果有加密字段，可在这里解密
            result.append({
                'transaction_id': t.transaction_id,
                'source_account_id': t.source_account_id,
                'destination_account_id': t.destination_account_id,
                'amount': float(t.amount),
                'transaction_type': t.transaction_type,
                'status': t.status,
                'timestamp': t.timestamp.isoformat(),
                'details': decrypt_data(t.encrypted_details) if t.encrypted_details else None
            })
        return result
    finally:
        session.close()
