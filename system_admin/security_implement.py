from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI
from config.mybank_db import SecurityLogs

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

def view_security_logs(admin_user, limit=50):
    """
    查看最近的安全日志，如入侵检测、异常登录等
    需在数据库中有 SecurityLogs 表
    """
    session = Session()
    try:
        logs = session.query(SecurityLogs).order_by(SecurityLogs.created_at.desc()).limit(limit).all()
        result = []
        for log in logs:
            result.append({
                'security_log_id': log.security_log_id,
                'event_type': log.event_type,
                'description': log.description,
                'user_id': log.user_id,
                'created_at': log.created_at.isoformat()
            })
        return result
    finally:
        session.close()

def perform_system_backup(admin_user, backup_destination):
    """
    模拟执行系统备份操作（数据库导出、文件备份等）
    这里只是示例，实际可调用命令行或云API
    """
    # 示例：执行一条mysqldump或pg_dump命令(视数据库而定)
    # 也可以调用云端API做镜像备份
    # 这里只是示例返回
    return f"Backup started. Destination: {backup_destination}"

def apply_system_patch(admin_user, patch_info):
    """
    模拟应用系统补丁
    在真实场景中可能需要SSH到服务器，或调用自动化部署脚本
    """
    # 这里可以做审计日志记录
    # audit.log_operation(admin_user.user_id, "apply_patch", patch_info)
    return f"Patch '{patch_info}' applied successfully."