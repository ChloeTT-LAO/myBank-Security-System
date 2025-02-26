# audit.py
from config.mybank_db import AuditLog
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
import datetime

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

def log_operation(user_id: int, operation: str, details: str = ""):
    session = Session()
    try:
        log_entry = AuditLog(
            user_id=user_id,
            operation=operation,
            details=details,
            log_time=datetime.datetime.now(tz=datetime.timezone.utc)
        )
        session.add(log_entry)
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()