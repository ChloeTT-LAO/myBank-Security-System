from sqlalchemy import Column, Integer, String, Text, DECIMAL, DateTime, Date, Enum, ForeignKey, LargeBinary, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum
import datetime

Base = declarative_base()


# 1. Role and Rights Management (Optional)
class RoleType(enum.Enum):
    client = "client"
    bank_employee = "bank_employee"
    system_admin = "system_admin"


# 2. user management
class Users(Base):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(RoleType), nullable=False)
    public_key = Column(Text)
    totp_secret = Column(String(50))
    hmac_key = Column(String(64))
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(DateTime(timezone=True), nullable=True)
    last_password_change = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))
    require_password_change = Column(Boolean, default=False)
    webauthn_data = Column(Text,  nullable=True)

    # Plaintext names, telephone numbers, and addresses are no longer stored, but encrypted:
    encrypted_name = Column(LargeBinary)
    name_nonce = Column(LargeBinary(12))
    encrypted_phone = Column(LargeBinary)
    phone_nonce = Column(LargeBinary(12))
    encrypted_address = Column(LargeBinary)
    address_nonce = Column(LargeBinary(12))

    key_name = Column(String(50))
    key_version = Column(String(50))
    last_updated_by = Column(Integer, ForeignKey('users.user_id'))
    last_updated_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc),
                        onupdate=datetime.datetime.now(tz=datetime.timezone.utc))

    # relationship
    accounts = relationship("Accounts", foreign_keys="[Accounts.user_id]", back_populates="user")
    sent_messages = relationship("Messages", foreign_keys="[Messages.sender_id]", back_populates="sender")
    received_messages = relationship("Messages", foreign_keys="[Messages.receiver_id]", back_populates="receiver")
    sessions = relationship("UserSessions", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    security_logs = relationship("SecurityLogs", back_populates="user")


# 3. Related to customer service operations

class Accounts(Base):
    __tablename__ = 'accounts'
    account_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    # Account numbers are encrypted as sensitive information:
    encrypted_account_number = Column(LargeBinary, nullable=False)
    account_number_nonce = Column(LargeBinary(12), nullable=False)
    account_number_hash = Column(String(64), index=True)
    key_version = Column(String(50))
    key_name = Column(String(50))

    balance = Column(DECIMAL(15, 2), default=0.00)
    account_type = Column(String(50))
    created_at = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))
    is_frozen = Column(Boolean, default=False)
    freeze_reason = Column(String(255))
    frozen_at = Column(DateTime(timezone=True))
    frozen_by = Column(Integer, ForeignKey('users.user_id'))
    unfrozen_at = Column(DateTime(timezone=True))
    unfrozen_by = Column(Integer, ForeignKey('users.user_id'))
    unfreeze_reason = Column(String(255))

    user = relationship("Users", foreign_keys=[user_id], back_populates="accounts")
    transactions_source = relationship("Transactions", foreign_keys="[Transactions.source_account_id]",
                                       back_populates="source_account")
    transactions_destination = relationship("Transactions", foreign_keys="[Transactions.destination_account_id]",
                                            back_populates="destination_account")
    frozen_by_user = relationship("Users", foreign_keys=[frozen_by])
    unfrozen_by_user = relationship("Users", foreign_keys=[unfrozen_by])


class Transactions(Base):
    __tablename__ = 'transactions'
    transaction_id = Column(Integer, primary_key=True, autoincrement=True)
    source_account_id = Column(Integer, ForeignKey('accounts.account_id'))
    destination_account_id = Column(Integer, ForeignKey('accounts.account_id'))
    amount = Column(DECIMAL(15, 2), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))
    transaction_type = Column(String(50))  #
    status = Column(String(50), default='pending')
    integrity_checksum = Column(String(255))
    # If the transaction has sensitive notes or postscripts, use encrypted storage
    encrypted_note = Column(LargeBinary)
    note_nonce = Column(LargeBinary(12))
    key_version = Column(String(50))
    key_name = Column(String(50))
    transaction_signature = Column(String(255), nullable=True)
    requires_additional_verification = Column(Boolean, default=False)
    verification_status = Column(String(50), default='not_required')  # 'not_required', 'pending', 'verified', 'failed'
    is_suspicious = Column(Boolean, default=False)
    suspicious_reason = Column(String(255))
    processed_by_employee = Column(Integer, ForeignKey('users.user_id'))

    source_account = relationship("Accounts", foreign_keys=[source_account_id], back_populates="transactions_source")
    destination_account = relationship("Accounts", foreign_keys=[destination_account_id],
                                       back_populates="transactions_destination")


class Messages(Base):
    __tablename__ = 'messages'
    message_id = Column(Integer, primary_key=True, autoincrement=True)
    sender_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    receiver_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)

    key_version = Column(String(50))
    key_name = Column(String(50))
    nonce = Column(LargeBinary(12))
    ciphertext = Column(LargeBinary)

    sent_at = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))
    read_status = Column(String(50), default='unread')

    sender = relationship("Users", foreign_keys=[sender_id], back_populates="sent_messages")
    receiver = relationship("Users", foreign_keys=[receiver_id], back_populates="received_messages")


# 4. login and audit

class UserSessions(Base):
    __tablename__ = 'user_sessions'
    session_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    session_token = Column(String(255), nullable=False, unique=True)
    login_time = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))
    logout_time = Column(DateTime(timezone=True))
    user_agent = Column(String(512), nullable=True)
    last_activity = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))

    user = relationship("Users", back_populates="sessions")


class AuditLog(Base):
    __tablename__ = 'audit_log'
    log_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    operation = Column(String(255), nullable=False)
    details = Column(Text)
    log_time = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)

    user = relationship("Users", back_populates="audit_logs")


# 5. System maintenance and security management

class KeyManagement(Base):
    __tablename__ = 'key_management'
    key_id = Column(Integer, primary_key=True, autoincrement=True)
    key_name = Column(String(50), nullable=False)
    key_type = Column(String(50), nullable=False)
    key_version = Column(String(50), nullable=False)
    key_value = Column(Text, nullable=False)
    expiry_date = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))


class SecurityLogs(Base):
    __tablename__ = 'security_logs'
    security_log_id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(100), nullable=False)
    description = Column(Text)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    created_at = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))
    user_agent = Column(String(512), nullable=True)
    ip_address = Column(String(50), nullable=True)

    user = relationship("Users", back_populates="security_logs")


class BlockchainBlock(Base):
    __tablename__ = 'blockchain_blocks'

    block_id = Column(Integer, primary_key=True, autoincrement=True)
    previous_hash = Column(String(64))
    merkle_root = Column(String(64))
    timestamp = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))
    nonce = Column(Integer)
    difficulty = Column(Integer)
    data_count = Column(Integer)
    block_hash = Column(String(64))


# A record of transactions stored on the blockchain
class BlockchainTransaction(Base):
    __tablename__ = 'blockchain_transactions'

    tx_id = Column(Integer, primary_key=True, autoincrement=True)
    block_id = Column(Integer)
    transaction_id = Column(Integer)
    transaction_hash = Column(String(64))
    transaction_data = Column(Text)
    timestamp = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))
