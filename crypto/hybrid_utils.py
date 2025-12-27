from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path


KEY_DIR = Path("keys")


def load_public_key():
    """
    Loads RSA public key from disk.
    """
    with open(KEY_DIR / "public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )


def load_private_key():
    """
    Loads encrypted RSA private key from disk.
    Prompts user for password.
    """
    password = input("Enter private key password: ").encode()

    with open(KEY_DIR / "private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=password,
            backend=default_backend()
        )


def encrypt_aes_key(aes_key: bytes) -> bytes:
    """
    Encrypts AES key using RSA public key (OAEP).
    """
    public_key = load_public_key()

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key


def decrypt_aes_key(encrypted_aes_key: bytes) -> bytes:
    """
    Decrypts AES key using RSA private key.
    """
    private_key = load_private_key()

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key
