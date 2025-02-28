import hashlib
import json
import hmac
from decimal import Decimal
from typing import Dict, Any, Optional
import pyotp
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.mybank_db import Transactions, Users, SecurityLogs
from config.config import DATABASE_URI
from security.encryption import compute_hmac_sha256
import datetime

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

# 定义高风险交易阈值
HIGH_VALUE_THRESHOLD = Decimal('10000.00')  # 高额交易阈值
UNUSUAL_TRANSACTION_TYPES = ["international_transfer", "crypto_exchange"]


def generate_transaction_hash(transaction_data: Dict[str, Any]) -> str:
    """
    为交易生成哈希值，用于完整性验证
    """
    # 创建交易数据的规范化表示
    canonical_data = {
        "source_account_id": transaction_data.get("source_account_id"),
        "destination_account_id": transaction_data.get("destination_account_id"),
        "amount": str(transaction_data.get("amount")),
        "transaction_type": transaction_data.get("transaction_type"),
        "timestamp": transaction_data.get("timestamp").isoformat() if isinstance(transaction_data.get("timestamp"),
                                                                                 datetime.datetime) else transaction_data.get(
            "timestamp"),
        "details": transaction_data.get("details", "")
    }

    # 将数据转换为JSON字符串并排序键，确保一致性
    canonical_json = json.dumps(canonical_data, sort_keys=True)

    # 计算哈希值
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()


def verify_transaction_integrity(transaction_id: int) -> bool:
    """
    验证交易记录的完整性
    """
    session = Session()
    try:
        transaction = session.query(Transactions).filter_by(transaction_id=transaction_id).first()
        if not transaction:
            return False

        # 只有存储了完整性校验和的交易才能验证
        if not transaction.integrity_checksum:
            return False

        # 从交易记录创建交易数据字典
        transaction_data = {
            "source_account_id": transaction.source_account_id,
            "destination_account_id": transaction.destination_account_id,
            "amount": transaction.amount,
            "transaction_type": transaction.transaction_type,
            "timestamp": transaction.timestamp,
            "details": transaction.encrypted_details  # 注意这里使用加密后的详情
        }

        # 生成当前数据的哈希值
        current_hash = generate_transaction_hash(transaction_data)

        # 比较与存储的哈希值
        return current_hash == transaction.integrity_checksum
    finally:
        session.close()


def generate_transaction_signature(transaction_data: Dict[str, Any], hmac_key: bytes) -> str:
    """
    使用HMAC为交易生成数字签名
    """
    # 创建交易数据的规范化表示
    canonical_data = {
        "source_account_id": transaction_data.get("source_account_id"),
        "destination_account_id": transaction_data.get("destination_account_id"),
        "amount": str(transaction_data.get("amount")),
        "transaction_type": transaction_data.get("transaction_type"),
        "timestamp": transaction_data.get("timestamp").isoformat() if isinstance(transaction_data.get("timestamp"),
                                                                                 datetime.datetime) else transaction_data.get(
            "timestamp"),
        "details": transaction_data.get("details", "")
    }

    # 将数据转换为JSON字符串
    canonical_json = json.dumps(canonical_data, sort_keys=True)

    # 计算HMAC
    return compute_hmac_sha256(canonical_json.encode('utf-8'), hmac_key)


def verify_transaction_signature(transaction_data: Dict[str, Any], signature: str, hmac_key: bytes) -> bool:
    """
    验证交易签名
    """
    expected_signature = generate_transaction_signature(transaction_data, hmac_key)
    return hmac.compare_digest(expected_signature, signature)


def is_high_risk_transaction(transaction_data: Dict[str, Any]) -> bool:
    """
    检查交易是否为高风险交易
    """
    # 检查交易金额是否超过阈值
    if Decimal(str(transaction_data.get("amount", 0))) >= HIGH_VALUE_THRESHOLD:
        return True

    # 检查交易类型是否为不常见类型
    if transaction_data.get("transaction_type") in UNUSUAL_TRANSACTION_TYPES:
        return True

    # 可以添加更多的风险检查逻辑

    return False


def log_transaction_verification(transaction_id: int, user_id: int, verification_type: str, is_success: bool,
                                 details: str = ""):
    """
    记录交易验证事件
    """
    session = Session()
    try:
        status = "success" if is_success else "failed"
        security_log = SecurityLogs(
            event_type=f"transaction_{verification_type}_{status}",
            description=f"Transaction {transaction_id} {verification_type} verification {status}. {details}",
            user_id=user_id,
            created_at=datetime.datetime.now(tz=datetime.timezone.utc)
        )
        session.add(security_log)
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"Error logging transaction verification: {str(e)}")
    finally:
        session.close()


def require_additional_verification(transaction_data: Dict[str, Any]) -> bool:
    """
    确定交易是否需要额外验证
    """
    # 高风险交易需要额外验证
    if is_high_risk_transaction(transaction_data):
        return True

    # 可以添加更多的触发条件

    return False


def verify_high_value_transaction(transaction_id: int, user_id: int, verification_code: str) -> bool:
    """
    完成高额交易的额外验证
    """
    session = Session()
    try:
        transaction = session.query(Transactions).filter_by(transaction_id=transaction_id).first()
        if not transaction:
            return False

        user = session.query(Users).filter_by(user_id=user_id).first()
        if not user:
            return False

        # 使用TOTP进行额外验证
        totp = pyotp.TOTP(user.totp_secret)
        verification_result = totp.verify(verification_code)

        # 记录验证结果
        log_transaction_verification(
            transaction_id,
            user_id,
            "additional",
            verification_result,
            "High value transaction additional verification"
        )

        return verification_result
    finally:
        session.close()