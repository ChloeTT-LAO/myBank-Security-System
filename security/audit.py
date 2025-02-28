import datetime
from config.mybank_db import AuditLog, SecurityLogs
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def log_operation(user_id: int, operation: str, details: str = "", ip_address: str = None, user_agent: str = None):
    """
    记录用户操作到审计日志
    """
    session = Session()
    try:
        log_entry = AuditLog(
            user_id=user_id,
            operation=operation,
            details=details,
            log_time=datetime.datetime.now(tz=datetime.timezone.utc),
            ip_address=ip_address,
            user_agent=user_agent
        )
        session.add(log_entry)
        session.commit()
        return log_entry.log_id
    except Exception as e:
        session.rollback()
        print(f"Error logging operation: {str(e)}")
        return None
    finally:
        session.close()


def log_security_event(user_id: int, event_type: str, description: str, ip_address: str = None, user_agent: str = None):
    """
    记录安全事件
    """
    session = Session()
    try:
        security_log = SecurityLogs(
            user_id=user_id,
            event_type=event_type,
            description=description,
            created_at=datetime.datetime.now(tz=datetime.timezone.utc),
            ip_address=ip_address,
            user_agent=user_agent
        )
        session.add(security_log)
        session.commit()
        return security_log.security_log_id
    except Exception as e:
        session.rollback()
        print(f"Error logging security event: {str(e)}")
        return None
    finally:
        session.close()


def get_user_audit_logs(user_id: int, limit: int = 100, offset: int = 0, operation_type: str = None):
    """
    获取用户的操作日志
    """
    session = Session()
    try:
        query = session.query(AuditLog).filter(AuditLog.user_id == user_id)

        if operation_type:
            query = query.filter(AuditLog.operation == operation_type)

        logs = query.order_by(AuditLog.log_time.desc()).limit(limit).offset(offset).all()

        result = []
        for log in logs:
            result.append({
                "log_id": log.log_id,
                "operation": log.operation,
                "details": log.details,
                "log_time": log.log_time.isoformat(),
                "ip_address": log.ip_address
            })

        return result
    finally:
        session.close()


def get_security_logs(admin_user_id: int, limit: int = 100, offset: int = 0, event_type: str = None,
                      user_id: int = None):
    """
    管理员获取安全日志
    """
    session = Session()
    try:
        query = session.query(SecurityLogs)

        if event_type:
            query = query.filter(SecurityLogs.event_type == event_type)

        if user_id:
            query = query.filter(SecurityLogs.user_id == user_id)

        logs = query.order_by(SecurityLogs.created_at.desc()).limit(limit).offset(offset).all()

        result = []
        for log in logs:
            result.append({
                "security_log_id": log.security_log_id,
                "user_id": log.user_id,
                "event_type": log.event_type,
                "description": log.description,
                "created_at": log.created_at.isoformat(),
                "ip_address": log.ip_address,
                "user_agent": log.user_agent
            })

        # 记录管理员查看日志的操作
        log_operation(
            admin_user_id,
            "view_security_logs",
            f"Admin viewed security logs. Filters: event_type={event_type}, user_id={user_id}"
        )

        return result
    finally:
        session.close()