import hashlib
import json
import time
import datetime
from typing import Dict, List, Any, Optional
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from config.config import DATABASE_URI
from config.mybank_db import Base, Transactions
from security.audit import log_operation

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


# 区块链存储的区块
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


# 区块链存储的交易记录
class BlockchainTransaction(Base):
    __tablename__ = 'blockchain_transactions'

    tx_id = Column(Integer, primary_key=True, autoincrement=True)
    block_id = Column(Integer)
    transaction_id = Column(Integer)  # 原始交易ID
    transaction_hash = Column(String(64))
    transaction_data = Column(Text)
    timestamp = Column(DateTime(timezone=True), default=datetime.datetime.now(tz=datetime.timezone.utc))


class SimpleBlockchain:
    """简化的区块链实现"""

    def __init__(self):
        """初始化区块链"""
        self.difficulty = 2  # 挖矿难度

        # 检查是否需要创建创世区块
        session = Session()
        try:
            # 检查是否有区块
            block_count = session.query(BlockchainBlock).count()
            if block_count == 0:
                # 创建创世区块
                self._create_genesis_block()
        finally:
            session.close()

    def _create_genesis_block(self):
        """创建创世区块"""
        session = Session()
        try:
            # 创建创世区块数据
            genesis_data = {
                "message": "Genesis Block",
                "timestamp": datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
            }

            # 计算创世区块哈希
            genesis_hash = self._calculate_hash(
                previous_hash="0" * 64,
                merkle_root=self._calculate_merkle_root([genesis_data]),
                timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
                nonce=0
            )

            # 创建创世区块
            genesis_block = BlockchainBlock(
                previous_hash="0" * 64,
                merkle_root=self._calculate_merkle_root([genesis_data]),
                timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
                nonce=0,
                difficulty=self.difficulty,
                data_count=1,
                block_hash=genesis_hash
            )

            session.add(genesis_block)
            session.commit()

            # 创建创世交易
            genesis_tx = BlockchainTransaction(
                block_id=genesis_block.block_id,
                transaction_id=0,
                transaction_hash=hashlib.sha256(json.dumps(genesis_data).encode()).hexdigest(),
                transaction_data=json.dumps(genesis_data),
                timestamp=datetime.datetime.now(tz=datetime.timezone.utc)
            )

            session.add(genesis_tx)
            session.commit()

            print(f"创世区块已创建，哈希: {genesis_hash}")
        except Exception as e:
            session.rollback()
            print(f"创建创世区块失败: {str(e)}")
        finally:
            session.close()

    def _calculate_hash(self, previous_hash: str, merkle_root: str, timestamp: datetime.datetime, nonce: int) -> str:
        """计算区块哈希"""
        block_header = f"{previous_hash}{merkle_root}{timestamp.isoformat()}{nonce}"
        return hashlib.sha256(block_header.encode()).hexdigest()

    def _calculate_merkle_root(self, data_list: List[Dict[str, Any]]) -> str:
        """计算梅克尔根"""
        if not data_list:
            return "0" * 64

        # 计算每个数据项的哈希
        hashes = [hashlib.sha256(json.dumps(data).encode()).hexdigest() for data in data_list]

        # 如果只有一个哈希，直接返回
        if len(hashes) == 1:
            return hashes[0]

        # 不断合并哈希，直到只剩一个
        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])  # 如果是奇数，复制最后一个

            temp = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                temp.append(hashlib.sha256(combined.encode()).hexdigest())

            hashes = temp

        return hashes[0]

    def _mine_block(self, previous_hash: str, merkle_root: str, timestamp: datetime.datetime) -> Tuple[str, int]:
        """挖矿，找到符合难度的区块哈希"""
        nonce = 0
        block_hash = self._calculate_hash(previous_hash, merkle_root, timestamp, nonce)

        while not block_hash.startswith("0" * self.difficulty):
            nonce += 1
            block_hash = self._calculate_hash(previous_hash, merkle_root, timestamp, nonce)

        return block_hash, nonce

    def add_transaction(self, transaction_id: int) -> Dict[str, Any]:
        """添加交易到区块链"""
        session = Session()
        try:
            # 获取交易数据
            transaction = session.query(Transactions).filter_by(transaction_id=transaction_id).first()
            if not transaction:
                raise ValueError(f"Transaction {transaction_id} not found")

            # 检查交易是否已经在区块链中
            existing = session.query(BlockchainTransaction).filter_by(transaction_id=transaction_id).first()
            if existing:
                return {
                    "success": False,
                    "message": f"Transaction {transaction_id} already in blockchain",
                    "block_id": existing.block_id,
                    "tx_id": existing.tx_id
                }

            # 准备交易数据
            tx_data = {
                "transaction_id": transaction.transaction_id,
                "source_account_id": transaction.source_account_id,
                "destination_account_id": transaction.destination_account_id,
                "amount": str(transaction.amount),
                "transaction_type": transaction.transaction_type,
                "status": transaction.status,
                "timestamp": transaction.timestamp.isoformat(),
                # 不包含加密的敏感数据
            }

            # 计算交易哈希
            tx_hash = hashlib.sha256(json.dumps(tx_data).encode()).hexdigest()

            # 获取待处理的交易
            pending_txs = session.query(BlockchainTransaction).filter_by(block_id=None).all()

            # 将当前交易加入待处理列表
            current_tx = BlockchainTransaction(
                transaction_id=transaction_id,
                transaction_hash=tx_hash,
                transaction_data=json.dumps(tx_data),
                timestamp=datetime.datetime.now(tz=datetime.timezone.utc)
            )
            session.add(current_tx)
            session.commit()

            # 刷新以获取ID
            session.refresh(current_tx)

            # 更新待处理列表
            pending_txs.append(current_tx)

            # 如果待处理交易达到10个，创建新区块
            if len(pending_txs) >= 10:
                return self._create_new_block(session, pending_txs)

            return {
                "success": True,
                "message": "Transaction added to pending pool",
                "tx_id": current_tx.tx_id
            }
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def _create_new_block(self, session, pending_txs: List[BlockchainTransaction]) -> Dict[str, Any]:
        """创建新区块"""
        try:
            # 获取最后一个区块
            last_block = session.query(BlockchainBlock).order_by(BlockchainBlock.block_id.desc()).first()

            # 准备区块数据
            previous_hash = last_block.block_hash
            timestamp = datetime.datetime.now(tz=datetime.timezone.utc)

            # 准备交易数据列表
            tx_data_list = [json.loads(tx.transaction_data) for tx in pending_txs]

            # 计算梅克尔根
            merkle_root = self._calculate_merkle_root(tx_data_list)

            # 挖矿，找到符合难度的哈希
            block_hash, nonce = self._mine_block(previous_hash, merkle_root, timestamp)

            # 创建新区块
            new_block = BlockchainBlock(
                previous_hash=previous_hash,
                merkle_root=merkle_root,
                timestamp=timestamp,
                nonce=nonce,
                difficulty=self.difficulty,
                data_count=len(pending_txs),
                block_hash=block_hash
            )

            session.add(new_block)
            session.commit()

            # 刷新以获取ID
            session.refresh(new_block)

            # 更新待处理交易的区块ID
            for tx in pending_txs:
                tx.block_id = new_block.block_id

            session.commit()

            return {
                "success": True,
                "message": "New block created",
                "block_id": new_block.block_id,
                "block_hash": block_hash,
                "transaction_count": len(pending_txs)
            }
        except Exception as e:
            session.rollback()
            raise e

    def verify_transaction(self, transaction_id: int) -> Dict[str, Any]:
        """验证交易是否在区块链中，以及它的完整性"""
        session = Session()
        try:
            # 查找交易
            blockchain_tx = session.query(BlockchainTransaction).filter_by(transaction_id=transaction_id).first()

            if not blockchain_tx:
                return {
                    "verified": False,
                    "message": f"Transaction {transaction_id} not found in blockchain"
                }

            # 如果交易还未被包含在区块中
            if not blockchain_tx.block_id:
                return {
                    "verified": False,
                    "message": f"Transaction {transaction_id} is pending, not yet in a block"
                }

            # 获取区块
            block = session.query(BlockchainBlock).filter_by(block_id=blockchain_tx.block_id).first()

            if not block:
                return {
                    "verified": False,
                    "message": f"Block {blockchain_tx.block_id} not found"
                }

            # 验证交易哈希
            tx_data = json.loads(blockchain_tx.transaction_data)
            calculated_hash = hashlib.sha256(json.dumps(tx_data).encode()).hexdigest()

            if calculated_hash != blockchain_tx.transaction_hash:
                return {
                    "verified": False,
                    "message": "Transaction data has been tampered with"
                }

            # 验证区块哈希
            calculated_block_hash = self._calculate_hash(
                block.previous_hash,
                block.merkle_root,
                block.timestamp,
                block.nonce
            )

            if calculated_block_hash != block.block_hash:
                return {
                    "verified": False,
                    "message": "Block data has been tampered with"
                }

            # 验证梅克尔根
            # 获取区块中的所有交易
            block_txs = session.query(BlockchainTransaction).filter_by(block_id=block.block_id).all()
            tx_data_list = [json.loads(tx.transaction_data) for tx in block_txs]

            calculated_merkle_root = self._calculate_merkle_root(tx_data_list)

            if calculated_merkle_root != block.merkle_root:
                return {
                    "verified": False,
                    "message": "Block's merkle root is invalid"
                }

            # 所有验证通过
            return {
                "verified": True,
                "message": f"Transaction {transaction_id} verified in block {block.block_id}",
                "block_id": block.block_id,
                "block_hash": block.block_hash,
                "timestamp": block.timestamp.isoformat()
            }
        finally:
            session.close()

    def get_blockchain_info(self) -> Dict[str, Any]:
        """获取区块链信息"""
        session = Session()
        try:
            # 获取区块总数
            block_count = session.query(BlockchainBlock).count()

            # 获取交易总数
            tx_count = session.query(BlockchainTransaction).filter(BlockchainTransaction.block_id.isnot(None)).count()

            # 获取最后一个区块
            last_block = session.query(BlockchainBlock).order_by(BlockchainBlock.block_id.desc()).first()

            # 获取待处理的交易数
            pending_count = session.query(BlockchainTransaction).filter_by(block_id=None).count()

            return {
                "block_count": block_count,
                "transaction_count": tx_count,
                "pending_count": pending_count,
                "last_block": {
                    "block_id": last_block.block_id if last_block else None,
                    "block_hash": last_block.block_hash if last_block else None,
                    "timestamp": last_block.timestamp.isoformat() if last_block else None,
                    "difficulty": self.difficulty
                }
            }
        finally:
            session.close()


# 创建区块链实例
blockchain = SimpleBlockchain()


def record_transaction(transaction_id: int, user_id: int = None) -> Dict[str, Any]:
    """将交易记录到区块链"""
    result = blockchain.add_transaction(transaction_id)

    # 记录操作
    if user_id:
        log_operation(
            user_id,
            "blockchain_record",
            f"Recorded transaction {transaction_id} to blockchain"
        )

    return result


def verify_transaction_integrity(transaction_id: int, user_id: int = None) -> Dict[str, Any]:
    """验证交易完整性"""
    result = blockchain.verify_transaction(transaction_id)

    # 记录操作
    if user_id:
        log_operation(
            user_id,
            "blockchain_verify",
            f"Verified transaction {transaction_id} on blockchain, result: {result['verified']}"
        )

    return result


def get_blockchain_status() -> Dict[str, Any]:
    """获取区块链状态信息"""
    return blockchain.get_blockchain_info()