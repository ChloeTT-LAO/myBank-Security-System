import hashlib
import json
import hmac
import pyotp
from decimal import Decimal
from typing import Dict, Any, Optional, Union
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.mybank_db import Transactions, Users, SecurityLogs, Accounts
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
            "details": transaction.encrypted_note  # 注意这里使用加密后的详情
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
    amount = transaction_data.get("amount", 0)
    if isinstance(amount, str):
        amount = Decimal(amount)

    if amount >= HIGH_VALUE_THRESHOLD:
        return True

    # 检查交易类型是否为不常见类型
    if transaction_data.get("transaction_type") in UNUSUAL_TRANSACTION_TYPES:
        return True

    # 可以添加更多的风险检查逻辑，例如跨国交易、新账户大额交易等

    return False


def require_additional_verification(transaction_data: Dict[str, Any]) -> bool:
    """
    确定交易是否需要额外验证
    """
    # 高风险交易需要额外验证
    if is_high_risk_transaction(transaction_data):
        return True

    # 其他可能需要验证的情况
    # 例如，不常用地点的交易，异常交易模式等

    return False


def verify_high_value_transaction(transaction_id: Optional[int], user_id: int, verification_code: str) -> bool:
    """
    完成高额交易的额外验证
    如果transaction_id为None，只验证码验证，不绑定到特定交易
    """
    session = Session()
    try:
        # 验证是否有效交易（如果提供了交易ID）
        if transaction_id is not None:
            transaction = session.query(Transactions).filter_by(transaction_id=transaction_id).first()
            if not transaction:
                return False

        # 获取用户TOTP密钥
        user = session.query(Users).filter_by(user_id=user_id).first()
        if not user:
            return False

        # 使用TOTP进行额外验证
        totp = pyotp.TOTP(user.totp_secret)
        verification_result = totp.verify(verification_code)

        # 如果有交易ID，记录验证结果
        if transaction_id is not None:
            # 更新交易验证状态
            transaction = session.query(Transactions).filter_by(transaction_id=transaction_id).first()
            if transaction:
                transaction.verification_status = 'verified' if verification_result else 'failed'
                session.commit()

            # 记录验证事件
            security_log = SecurityLogs(
                user_id=user_id,
                event_type="high_value_transaction_verification",
                description=f"High value transaction {transaction_id} verification {'success' if verification_result else 'failed'}",
                created_at=datetime.datetime.now(tz=datetime.timezone.utc)
            )
            session.add(security_log)
            session.commit()

        return verification_result
    except Exception as e:
        session.rollback()
        print(f"Error in high value transaction verification: {str(e)}")
        return False
    finally:
        session.close()