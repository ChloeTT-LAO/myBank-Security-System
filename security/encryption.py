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
    Generate a 256-bit symmetric key
    """
    return AESGCM.generate_key(bit_length=256)


def aes_256_gcm_encrypt(plaintext: bytes, aes_key, aad: bytes = None):
    """
    The plaintext is encrypted using AES-256-GCM
    :param plaintext: data to be encrypted (bytes)
    :param aad: Additional authentication data (optional) that participates in authentication when encrypted, but is not encrypted
    :return: Returns a triple (key, nonce, ciphertext)
    key: 256 bit key used by AESGCM for encryption
    nonce: randomly generated nonce (12 bytes recommended)
    ciphertext: indicates the encrypted ciphertext that contains the authentication label
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return nonce, ciphertext


def aes_256_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = None) -> bytes:
    """
    Use AES-256-GCM to decrypt the ciphertext
    :param key: key for encryption (256-bit)
    :param nonce: indicates the nonce used for encryption
    :param ciphertext: indicates the encrypted ciphertext (including the authentication label).
    :param aad: Additional authentication data (must be the same as when encrypted)
    :return: decrypted plain text (bytes)
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext


# ========== RSA encryption/decryption symmetric key ==========

def generate_rsa_keypair(key_size=2048):
    """
    Generate a pair of RSA keys (private + public key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt_symmetric_key(public_key, symmetric_key: bytes) -> bytes:
    """
    Encrypt symmetric keys with RSA public keys
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
    The symmetric key is decrypted by RSA private key
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
    Serializing an RSA private key to PEM format usually requires secure storage or encryption
    """

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return pem


def serialize_public_key_to_pem(public_key) -> bytes:
    """
    Serialize the RSA public key to PEM format
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def load_private_key_from_pem(pem_data: bytes):
    """
    Load RSA private keys from PEM bytes
    """
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None
    )
    return private_key


def load_public_key_from_pem(pem_data: bytes):
    """
    Load an RSA public key from PEM bytes
    """
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key


def generate_hmac_key() -> bytes:
    key = os.urandom(32)
    return key


def compute_hmac_sha256(message: bytes, key: bytes) -> str:
    key = bytes(key)
    mac = hmac.new(key, message, hashlib.sha256).hexdigest()
    return mac


def verify_hmac_sha256(message_str, current_user, hmac_value) -> bool:
    hmac_key_bytes = current_user.hmac_key
    computed_hmac = compute_hmac_sha256(message_str.encode('utf-8'), hmac_key_bytes)
    if computed_hmac != hmac_value:
        return False
    else:
        return True
