# loans.py
import datetime
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
from config.mybank_db import Loans

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

def apply_for_loan(user_id: int, loan_amount: float, interest_rate: float, duration: str):
    session = Session()
    try:
        new_loan = Loans(
            user_id=user_id,
            loan_amount=loan_amount,
            interest_rate=interest_rate,
            duration=duration,
            status='applied',
            applied_date=datetime.datetime.now(tz=datetime.timezone.utc)
        )
        session.add(new_loan)
        session.commit()
        return new_loan
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()