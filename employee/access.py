from config.config import DATABASE_URI
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.mybank_db import Accounts, Users, Transactions
from security.encryption import aes_256_gcm_decrypt
from security.key_management import retrieve_key_from_db
from security.audit import log_operation

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
        if not customer or customer.role.value != 'client':
            raise Exception("The specified user is not a valid customer.")

        accounts = session.query(Accounts).filter_by(user_id=customer_id).all()
        result = []
        for acc in accounts:
            # 尝试解密账号信息
            account_number = "Encrypted"
            try:
                if acc.encrypted_account_number and acc.account_number_nonce and acc.key_name:
                    aes_key, _ = retrieve_key_from_db(acc.key_name)
                    account_number = aes_256_gcm_decrypt(
                        aes_key,
                        acc.account_number_nonce,
                        acc.encrypted_account_number
                    ).decode('utf-8')
            except Exception as e:
                print(f"Error decrypting account number: {str(e)}")

            result.append({
                'account_id': acc.account_id,
                'account_number': account_number,
                'balance': float(acc.balance),
                'account_type': acc.account_type,
                'created_at': acc.created_at.isoformat() if acc.created_at else None,
                'status': 'Frozen' if getattr(acc, 'is_frozen', False) else 'Active'
            })

        # 记录操作
        log_operation(
            employee_user.user_id,
            "view_customer_accounts",
            f"Viewed accounts for customer {customer_id}"
        )

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
            # 尝试解密交易详情
            details = None
            try:
                if t.encrypted_note and t.note_nonce and t.key_name:
                    aes_key, _ = retrieve_key_from_db(t.key_name)
                    details = aes_256_gcm_decrypt(
                        aes_key,
                        t.note_nonce,
                        t.encrypted_note
                    ).decode('utf-8')
            except Exception as e:
                print(f"Error decrypting transaction details: {str(e)}")

            result.append({
                'transaction_id': t.transaction_id,
                'source_account_id': t.source_account_id,
                'destination_account_id': t.destination_account_id,
                'amount': float(t.amount),
                'transaction_type': t.transaction_type,
                'status': t.status,
                'timestamp': t.timestamp.isoformat() if t.timestamp else None,
                'details': details,
                'is_suspicious': getattr(t, 'is_suspicious', False),
                'suspicious_reason': getattr(t, 'suspicious_reason', None),
                'verification_status': getattr(t, 'verification_status', None)
            })

        # 记录操作
        log_operation(
            employee_user.user_id,
            "view_account_transactions",
            f"Viewed transactions for account {account_id}"
        )

        return result
    finally:
        session.close()