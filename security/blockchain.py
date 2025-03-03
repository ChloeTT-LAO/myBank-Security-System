import hashlib
import json
import datetime
from typing import Dict, List, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI
from config.mybank_db import Transactions, BlockchainBlock, BlockchainTransaction
from security.audit import log_operation

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


# Blockchain storage block


class SimpleBlockchain:
    """Simplified blockchain implementation"""

    def __init__(self):
        """Initialize the blockchain"""
        self.difficulty = 2  # Mining difficulty

        # Check if genesis block needs to be created
        session = Session()
        try:
            # Check if there are any blocks
            block_count = session.query(BlockchainBlock).count()
            if block_count == 0:
                # Create genesis block
                self._create_genesis_block()
        finally:
            session.close()

    def _create_genesis_block(self):
        """Create genesis block"""
        session = Session()
        try:
            # Create genesis block data
            genesis_data = {
                "message": "Genesis Block",
                "timestamp": datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
            }

            # Calculate genesis block hash
            genesis_hash = self._calculate_hash(
                previous_hash="0" * 64,
                merkle_root=self._calculate_merkle_root([genesis_data]),
                timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
                nonce=0
            )

            # Create genesis block
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

            # Create genesis transaction
            genesis_tx = BlockchainTransaction(
                block_id=genesis_block.block_id,
                transaction_id=0,
                transaction_hash=hashlib.sha256(json.dumps(genesis_data).encode()).hexdigest(),
                transaction_data=json.dumps(genesis_data),
                timestamp=datetime.datetime.now(tz=datetime.timezone.utc)
            )

            session.add(genesis_tx)
            session.commit()

            print(f"Genesis block created, hash: {genesis_hash}")
        except Exception as e:
            session.rollback()
            print(f"Failed to create genesis block: {str(e)}")
        finally:
            session.close()

    def _calculate_hash(self, previous_hash: str, merkle_root: str, timestamp: datetime.datetime, nonce: int) -> str:
        """Calculate block hash"""
        block_header = f"{previous_hash}{merkle_root}{timestamp.isoformat()}{nonce}"
        return hashlib.sha256(block_header.encode()).hexdigest()

    def _calculate_merkle_root(self, data_list: List[Dict[str, Any]]) -> str:
        """Calculate Merkle root"""
        if not data_list:
            return "0" * 64

        # Calculate hash for each data item
        hashes = [hashlib.sha256(json.dumps(data).encode()).hexdigest() for data in data_list]

        # If there's only one hash, return directly
        if len(hashes) == 1:
            return hashes[0]

        # Continuously merge hashes until only one remains
        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])  # If odd number, duplicate the last one

            temp = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                temp.append(hashlib.sha256(combined.encode()).hexdigest())

            hashes = temp

        return hashes[0]

    def _mine_block(self, previous_hash: str, merkle_root: str, timestamp: datetime.datetime) -> tuple[str, int]:
        """Mining, find block hash that meets difficulty"""
        nonce = 0
        block_hash = self._calculate_hash(previous_hash, merkle_root, timestamp, nonce)

        while not block_hash.startswith("0" * self.difficulty):
            nonce += 1
            block_hash = self._calculate_hash(previous_hash, merkle_root, timestamp, nonce)

        return block_hash, nonce

    def add_transaction(self, transaction_id: int) -> Dict[str, Any]:
        """Add a transaction to the blockchain"""
        session = Session()
        try:
            transaction = session.query(Transactions).filter_by(transaction_id=transaction_id).first()
            if not transaction:
                raise ValueError(f"Transaction {transaction_id} not found")

            # Check if the transaction is already in the blockchain
            existing = session.query(BlockchainTransaction).filter_by(transaction_id=transaction_id).first()
            if existing:
                return {
                    "success": False,
                    "message": f"Transaction {transaction_id} already in blockchain",
                    "block_id": existing.block_id,
                    "tx_id": existing.tx_id
                }

            # Prepare trading data
            tx_data = {
                "transaction_id": transaction.transaction_id,
                "source_account_id": transaction.source_account_id,
                "destination_account_id": transaction.destination_account_id,
                "amount": str(transaction.amount),
                "transaction_type": transaction.transaction_type,
                "status": transaction.status,
                "timestamp": transaction.timestamp.isoformat(),
                # Does not contain encrypted sensitive data
            }

            # Calculate transaction hash
            tx_hash = hashlib.sha256(json.dumps(tx_data).encode()).hexdigest()

            # Get pending transactions
            pending_txs = session.query(BlockchainTransaction).filter_by(block_id=None).all()

            # Add current transaction to pending list
            current_tx = BlockchainTransaction(
                transaction_id=transaction_id,
                transaction_hash=tx_hash,
                transaction_data=json.dumps(tx_data),
                timestamp=datetime.datetime.now(tz=datetime.timezone.utc)
            )
            session.add(current_tx)
            session.commit()

            # Refresh to get ID
            session.refresh(current_tx)

            # Update pending list
            pending_txs.append(current_tx)

            # If pending transactions reach 10, create new block
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
        """Create new block"""
        try:
            # Get the last block
            last_block = session.query(BlockchainBlock).order_by(BlockchainBlock.block_id.desc()).first()

            # Prepare block data
            previous_hash = last_block.block_hash
            timestamp = datetime.datetime.now(tz=datetime.timezone.utc)

            # Prepare transaction data list
            tx_data_list = [json.loads(tx.transaction_data) for tx in pending_txs]

            # Calculate Merkle root
            merkle_root = self._calculate_merkle_root(tx_data_list)

            # Mining, find hash that meets difficulty
            block_hash, nonce = self._mine_block(previous_hash, merkle_root, timestamp)

            # Create new block
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

            # Refresh to get ID
            session.refresh(new_block)

            # Update block IDs for pending transactions
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
        """Verify if transaction is in the blockchain and its integrity"""
        session = Session()
        try:
            # Find transaction
            blockchain_tx = session.query(BlockchainTransaction).filter_by(transaction_id=transaction_id).first()

            if not blockchain_tx:
                return {
                    "verified": False,
                    "message": f"Transaction {transaction_id} not found in blockchain"
                }

            # If transaction is not yet included in a block
            if not blockchain_tx.block_id:
                return {
                    "verified": False,
                    "message": f"Transaction {transaction_id} is pending, not yet in a block"
                }

            # Get the block
            block = session.query(BlockchainBlock).filter_by(block_id=blockchain_tx.block_id).first()

            if not block:
                return {
                    "verified": False,
                    "message": f"Block {blockchain_tx.block_id} not found"
                }

            # Verify transaction hash
            tx_data = json.loads(blockchain_tx.transaction_data)
            calculated_hash = hashlib.sha256(json.dumps(tx_data).encode()).hexdigest()

            if calculated_hash != blockchain_tx.transaction_hash:
                return {
                    "verified": False,
                    "message": "Transaction data has been tampered with"
                }

            # Verify block hash
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

            # Verify Merkle root
            # Get all transactions in the block
            block_txs = session.query(BlockchainTransaction).filter_by(block_id=block.block_id).all()
            tx_data_list = [json.loads(tx.transaction_data) for tx in block_txs]

            calculated_merkle_root = self._calculate_merkle_root(tx_data_list)

            if calculated_merkle_root != block.merkle_root:
                return {
                    "verified": False,
                    "message": "Block's merkle root is invalid"
                }

            # All verifications passed
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
        """Get blockchain information"""
        session = Session()
        try:
            # Get total number of blocks
            block_count = session.query(BlockchainBlock).count()

            # Get total number of transactions
            tx_count = session.query(BlockchainTransaction).filter(BlockchainTransaction.block_id.isnot(None)).count()

            # Get the last block
            last_block = session.query(BlockchainBlock).order_by(BlockchainBlock.block_id.desc()).first()

            # Get number of pending transactions
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


# Create blockchain instance
blockchain = SimpleBlockchain()


def record_transaction(transaction_id: int, user_id: int = None) -> Dict[str, Any]:
    """Record the transaction to the blockchain"""
    result = blockchain.add_transaction(transaction_id)

    if user_id:
        log_operation(
            user_id,
            "blockchain_record",
            f"Recorded transaction {transaction_id} to blockchain"
        )

    return result


def verify_transaction_integrity(transaction_id: int, user_id: int = None) -> Dict[str, Any]:
    """Verify transaction integrity"""
    result = blockchain.verify_transaction(transaction_id)

    # Record operation
    if user_id:
        log_operation(
            user_id,
            "blockchain_verify",
            f"Verified transaction {transaction_id} on blockchain, result: {result['verified']}"
        )

    return result


def get_blockchain_status() -> Dict[str, Any]:
    """Get blockchain status information"""
    return blockchain.get_blockchain_info()