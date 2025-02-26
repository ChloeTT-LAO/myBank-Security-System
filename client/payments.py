# payments.py
import datetime
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
from config.mybank_db import Accounts, BillPayments, RecurringPayments

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

def pay_bill(user_id: int, account_id: int, biller_name: str, amount: float, due_date_str: str):
    session = Session()
    try:
        account = session.query(Accounts).filter_by(account_id=account_id, user_id=user_id).first()
        if not account:
            raise Exception("Account not found or access denied.")
        if account.balance < amount:
            raise Exception("Insufficient funds.")
        account.balance -= amount
        due_date = datetime.datetime.strptime(due_date_str, '%Y-%m-%d').date()
        new_bill = BillPayments(
            account_id=account_id,
            biller_name=biller_name,
            amount=amount,
            due_date=due_date,
            payment_date=datetime.datetime.utcnow().date(),
            status='paid'
        )
        session.add(new_bill)
        session.commit()
        return new_bill
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def setup_recurring_payment(user_id: int, account_id: int, payment_amount: float, frequency: str, next_payment_date_str: str):
    session = Session()
    try:
        account = session.query(Accounts).filter_by(account_id=account_id, user_id=user_id).first()
        if not account:
            raise Exception("Account not found or access denied.")
        next_payment_date = datetime.datetime.strptime(next_payment_date_str, '%Y-%m-%d').date()
        new_recurring = RecurringPayments(
            account_id=account_id,
            payment_amount=payment_amount,
            frequency=frequency,
            next_payment_date=next_payment_date,
            status='active'
        )
        session.add(new_recurring)
        session.commit()
        return new_recurring
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()