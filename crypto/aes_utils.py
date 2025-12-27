from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def generate_aes_key() -> bytes:
    """
    Generates a secure random 256-bit AES key.
    """
    return AESGCM.generate_key(bit_length=256)


def encrypt_data(plaintext: bytes, key: bytes) -> tuple:
    """
    Encrypts data using AES-GCM.

    Returns:
        nonce, ciphertext, tag
    """
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)  # 96-bit nonce (recommended for GCM)

    ciphertext = aesgcm.encrypt(
        nonce=nonce,
        data=plaintext,
        associated_data=None
    )

    return nonce, ciphertext


def decrypt_data(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts AES-GCM encrypted data.
    Raises exception if authentication fails.
    """
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce=nonce,
        data=ciphertext,
        associated_data=None
    )

    return plaintext
