from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt_data(plaintext: bytes, key: bytes, aad: bytes = None) -> tuple:
    """
    Encrypt data using AES-GCM with optional AAD.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce

    ciphertext = aesgcm.encrypt(
        nonce=nonce,
        data=plaintext,
        associated_data=aad
    )

    return nonce, ciphertext


def decrypt_data(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes = None) -> bytes:
    """
    Decrypt AES-GCM encrypted data with optional AAD.
    """
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce=nonce,
        data=ciphertext,
        associated_data=aad
    )

    return plaintext
