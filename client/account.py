import hashlib

from config.config import DATABASE_URI
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.mybank_db import Accounts, Transactions, Users
from security.encryption import aes_256_gcm_encrypt
from security.key_management import retrieve_key_from_db

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
key_name = "user_account"


def create_account(user_id, account_type):
    session = Session()
    from uuid import uuid4
    account_number = str(uuid4().int)[:10]  # 生成10位账户号
    aes_key, key_version = retrieve_key_from_db(key_name)
    account_number_nonce, encrypted_account_number = aes_256_gcm_encrypt(account_number.encode('utf-8'), aes_key)
    account_number_hash = hashlib.sha256(account_number.encode('utf-8')).hexdigest()

    initial_balance = 0
    new_account = Accounts(
        user_id=user_id,
        encrypted_account_number=encrypted_account_number,
        account_number_nonce=account_number_nonce,
        key_version=key_version,
        key_name=key_name,
        balance=initial_balance,
        account_type=account_type,
        account_number_hash=account_number_hash
    )
    session.add(new_account)
    session.commit()

    return account_number


def get_account_info(user_id: int, account_id: int):
    """
    返回账户的基本信息和余额
    """
    session = Session()
    try:
        account = session.query(Accounts).filter_by(account_id=account_id, user_id=user_id).first()
        if not account:
            raise Exception("Account not found or access denied.")
        return {
            'account_id': account.account_id,
            'account_number': account.account_number,
            'balance': account.balance
        }
    finally:
        session.close()


def get_transactions(user_id: int, account_id: int):
    """
    查询与某账户相关的交易，并解密每笔交易的细节
    """
    session = Session()
    try:
        # 首先确认该 account_id 是否属于此 user
        account = session.query(Accounts).filter_by(account_id=account_id, user_id=user_id).first()
        if not account:
            raise Exception("Account not found or access denied.")

        # 查找该账户的所有交易(包括转出和转入)
        txs = session.query(Transactions).filter(
            (Transactions.source_account_id == account_id) |
            (Transactions.destination_account_id == account_id)
        ).order_by(Transactions.timestamp.desc()).all()

        result = []
        for t in txs:
            # 解密交易细节
            detail_plain = None
            if t.encrypted_details:
                detail_plain = decrypt_data(t.encrypted_details)

            result.append({
                'transaction_id': t.transaction_id,
                'source_account_id': t.source_account_id,
                'destination_account_id': t.destination_account_id,
                'amount': t.amount,
                'transaction_type': t.transaction_type,
                'status': t.status,
                'timestamp': t.timestamp.isoformat(),
                'details': detail_plain  # 解密后的内容
            })
        return result
    finally:
        session.close()


def update_personal_info(user_id: int, new_phone: str = None, new_address: str = None, new_name: str = None):
    """
    更新用户的个人信息。只修改有传入的新值，其他字段保持不变。
    """
    session = Session()
    try:
        user = session.query(Users).filter_by(user_id=user_id).first()
        if not user:
            raise Exception("User not found.")

        # 这里可以进行更多校验或安全检查

        if new_phone is not None:
            user.phone = new_phone

        if new_address is not None:
            # 如果要对地址加密，可以：
            addr_nonce, encrypted_addr = aes_256_gcm_encrypt(new_address)
            user.encrypted_address = encrypted_addr
            user.address = new_address

        if new_name is not None:
            user.name = new_name

        session.commit()
        return user
    except:
        session.rollback()
        raise
    finally:
        session.close()