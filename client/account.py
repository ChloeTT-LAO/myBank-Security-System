import hashlib
from config.config import DATABASE_URI
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.mybank_db import Accounts, Transactions, Users
from security.encryption import aes_256_gcm_encrypt, aes_256_gcm_decrypt
from security.key_management import retrieve_key_from_db
from security.audit import log_operation

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
key_name = "user_account"


def create_account(user_id, account_type):
    """
    创建新账户
    """
    session = Session()
    try:
        from uuid import uuid4
        account_number = str(uuid4().int)[:10]  # 生成10位账户号

        # 加密账号
        aes_key, key_version = retrieve_key_from_db(key_name)
        account_number_nonce, encrypted_account_number = aes_256_gcm_encrypt(account_number.encode('utf-8'), aes_key)

        # 为快速查找，同时存储账号的哈希值
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
            account_number_hash=account_number_hash,
            created_at=datetime.datetime.now(tz=datetime.timezone.utc),
            is_frozen=False
        )
        session.add(new_account)
        session.commit()

        # 记录操作
        log_operation(
            user_id,
            "create_account",
            f"Created new {account_type} account"
        )

        return account_number
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_account_info(user_id: int, account_id: int):
    """
    返回账户的基本信息和余额
    """
    session = Session()
    try:
        account = session.query(Accounts).filter_by(account_id=account_id, user_id=user_id).first()
        if not account:
            raise Exception("Account not found or access denied.")

        # 尝试解密账号
        account_number = "Encrypted"
        try:
            if account.encrypted_account_number and account.account_number_nonce and account.key_name:
                aes_key, _ = retrieve_key_from_db(account.key_name)
                account_number = aes_256_gcm_decrypt(
                    aes_key,
                    account.account_number_nonce,
                    account.encrypted_account_number
                ).decode('utf-8')
        except Exception as e:
            print(f"Error decrypting account number: {str(e)}")

        # 记录操作
        log_operation(
            user_id,
            "view_account_info",
            f"Viewed account {account_id} information"
        )

        return {
            'account_id': account.account_id,
            'account_number': account_number,
            'balance': float(account.balance),
            'account_type': account.account_type,
            'created_at': account.created_at.isoformat() if account.created_at else None,
            'status': 'Frozen' if getattr(account, 'is_frozen', False) else 'Active'
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
            try:
                if t.encrypted_note and t.note_nonce and t.key_name:
                    aes_key, _ = retrieve_key_from_db(t.key_name)
                    detail_plain = aes_256_gcm_decrypt(
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
                'details': detail_plain,
                'verification_status': getattr(t, 'verification_status', None)
            })

        # 记录操作
        log_operation(
            user_id,
            "view_transactions",
            f"Viewed transactions for account {account_id}"
        )

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

        # 获取加密密钥
        aes_key, key_version = retrieve_key_from_db(key_name=user.key_name)

        # 更新电话
        if new_phone is not None:
            phone_nonce, encrypted_phone = aes_256_gcm_encrypt(new_phone.encode('utf-8'), aes_key)
            user.encrypted_phone = encrypted_phone
            user.phone_nonce = phone_nonce

        # 更新地址
        if new_address is not None:
            address_nonce, encrypted_address = aes_256_gcm_encrypt(new_address.encode('utf-8'), aes_key)
            user.encrypted_address = encrypted_address
            user.address_nonce = address_nonce

        # 更新姓名
        if new_name is not None:
            name_nonce, encrypted_name = aes_256_gcm_encrypt(new_name.encode('utf-8'), aes_key)
            user.encrypted_name = encrypted_name
            user.name_nonce = name_nonce

        # 记录更新时间
        user.updated_at = datetime.datetime.now(tz=datetime.timezone.utc)

        session.commit()

        # 记录操作
        update_fields = []
        if new_phone: update_fields.append("phone")
        if new_address: update_fields.append("address")
        if new_name: update_fields.append("name")

        log_operation(
            user_id,
            "update_personal_info",
            f"Updated personal information: {', '.join(update_fields)}"
        )

        return user
    except:
        session.rollback()
        raise
    finally:
        session.close()