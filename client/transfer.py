import hashlib
from decimal import Decimal
from config.mybank_db import Accounts, Transactions
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
import datetime
from security.encryption import aes_256_gcm_encrypt
from security.key_management import retrieve_key_from_db

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
key_name = "user_transaction"


def transfer(source_account_number, destination_account_number, amount, note="Transfer"):
    session = Session()
    try:
        source_account = session.query(Accounts).filter_by(
            account_number_hash=hashlib.sha256(source_account_number.encode('utf-8')).hexdigest()).first()
        destination_account = session.query(Accounts).filter_by(
            account_number_hash=hashlib.sha256(destination_account_number.encode('utf-8')).hexdigest()).first()

        if not source_account or not destination_account:
            raise Exception("Source or destination account not found.")
        if source_account.balance < amount:
            raise Exception("Insufficient funds.")

        source_account.balance -= amount
        destination_account.balance += amount
        balance = source_account.balance

        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        note_nonce, encrypted_note = aes_256_gcm_encrypt(note.encode('utf-8'), aes_key)

        # 记录交易
        transaction = Transactions(
            source_account_id=source_account.account_id,  # 存款可能没有source
            destination_account_id=destination_account.account_id,
            amount=amount,
            transaction_type='Transfer',
            status='completed',
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            encrypted_note=encrypted_note,
            note_nonce=note_nonce,
            key_version=key_version,
            key_name=key_name
        )
        transaction_id = transaction.transaction_id
        session.add(transaction)
        session.commit()
        return transaction_id, balance

    except:
        session.rollback()
        raise
    finally:
        session.close()


def deposit(account_number, amount, note="Deposit"):
    session = Session()
    try:
        account = session.query(Accounts).filter_by(
            account_number_hash=hashlib.sha256(account_number.encode('utf-8')).hexdigest()).first()
        if not account:
            raise Exception("Account not found.")

        account.balance += (Decimal(amount))
        balance = account.balance

        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        note_nonce, encrypted_note = aes_256_gcm_encrypt(note.encode('utf-8'), aes_key)

        # 记录交易
        transaction = Transactions(
            source_account_id=None,  # 存款可能没有source
            destination_account_id=account.account_id,
            amount=amount,
            transaction_type='deposit',
            status='completed',
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            encrypted_note=encrypted_note,
            note_nonce=note_nonce,
            key_version=key_version,
            key_name=key_name
        )
        transaction_id = transaction.transaction_id
        session.add(transaction)
        session.commit()
        return transaction_id, balance

    except:
        session.rollback()
        raise
    finally:
        session.close()


def withdraw(account_number, amount, note="Deposit"):
    session = Session()
    try:
        account = session.query(Accounts).filter_by(
            account_number_hash=hashlib.sha256(account_number.encode('utf-8')).hexdigest()).first()
        if not account:
            raise Exception("Account not found.")

        if account.balance < amount:
            raise Exception("Insufficient funds.")

        account.balance -= amount
        balance = account.balance

        aes_key, key_version = retrieve_key_from_db(key_name=key_name)
        note_nonce, encrypted_note = aes_256_gcm_encrypt(note.encode('utf-8'), aes_key)

        # 记录交易
        transaction = Transactions(
            source_account_id=account.account_id,
            destination_account_id=None,
            amount=amount,
            transaction_type='withdraw',
            status='completed',
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            encrypted_note=encrypted_note,
            note_nonce=note_nonce,
            key_version=key_version,
            key_name=key_name
        )
        transaction_id = transaction.transaction_id
        session.add(transaction)
        session.commit()
        return transaction_id, balance

    except:
        session.rollback()
        raise
    finally:
        session.close()