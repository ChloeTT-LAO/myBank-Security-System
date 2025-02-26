import base64
import hashlib
import hmac
from sqlalchemy import create_engine
from config.config import DATABASE_URI
from sqlalchemy.orm import sessionmaker
import bcrypt
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def check_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def generate_aes_256_key() -> bytes:
    """
    生成 256 位对称密钥
    """
    return AESGCM.generate_key(bit_length=256)


def aes_256_gcm_encrypt(plaintext: bytes, aes_key, aad: bytes = None):
    """
    使用 AES-256-GCM 对明文进行加密
    :param plaintext: 需要加密的数据（bytes类型）
    :param aad: 附加认证数据（可选），该数据在加密时参与认证，但不加密
    :return: 返回一个三元组 (key, nonce, ciphertext)
             key: AESGCM 加密使用的 256 位密钥
             nonce: 随机生成的 nonce（推荐12字节）
             ciphertext: 加密后的密文，其中包含认证标签
    """

    # 生成一个随机的 nonce（推荐长度为12字节）
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    # 加密数据
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return nonce, ciphertext


def aes_256_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = None) -> bytes:
    """
    使用 AES-256-GCM 对密文进行解密
    :param key: 用于加密的密钥（256 位）
    :param nonce: 加密时使用的 nonce
    :param ciphertext: 加密后的密文（含认证标签）
    :param aad: 附加认证数据（必须与加密时一致）
    :return: 解密后的明文（bytes类型）
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext


# ========== RSA 加密/解密对称密钥 ==========

def generate_rsa_keypair(key_size=2048):
    """
    生成一对RSA密钥 (私钥 + 公钥)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt_symmetric_key(public_key, symmetric_key: bytes) -> bytes:
    """
    用RSA公钥加密对称密钥
    :param public_key: RSA公钥
    :param symmetric_key: 需要加密的对称密钥 (32字节)
    :return: 加密后的字节串
    """
    ciphertext = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt_symmetric_key(private_key, encrypted_key: bytes) -> bytes:
    """
    用RSA私钥解密得到对称密钥
    :param private_key: RSA私钥
    :param encrypted_key: RSA加密后的对称密钥
    :return: 原始对称密钥(32字节)
    """
    plaintext = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def serialize_private_key_to_pem(private_key) -> bytes:
    """
    将RSA私钥序列化为PEM格式，通常需要安全地存储或加密
    """

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # 生产环境建议加密
    )

    return pem


def serialize_public_key_to_pem(public_key) -> bytes:
    """
    将RSA公钥序列化为PEM格式
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def load_private_key_from_pem(pem_data: bytes):
    """
    从PEM字节串加载RSA私钥
    """
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None
    )
    return private_key


def load_public_key_from_pem(pem_data: bytes):
    """
    从PEM字节串加载RSA公钥
    """
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key


def generate_hmac_key() -> bytes:
    # 生成32字节的 HMAC 密钥，并以Base64字符串形式返回
    key = os.urandom(32)
    return key


def compute_hmac_sha256(message: bytes, key: bytes) -> str:
    mac = hmac.new(key, message, hashlib.sha256).hexdigest()
    return mac


def verify_hmac_sha256(message_str, current_user, hmac_value) -> bool:
    hmac_key_bytes = current_user.hmac_key
    computed_hmac = compute_hmac_sha256(message_str.encode('utf-8'), hmac_key_bytes)
    if computed_hmac != hmac_value:
        return False
    else:
        return True
