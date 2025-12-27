from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import os
from getpass import getpass


KEY_SIZE = 2048
KEY_DIR = Path("keys")


def generate_rsa_keys():
    """
    Generates an RSA key pair.
    The private key is encrypted using a password.
    """

    KEY_DIR.mkdir(exist_ok=True)

    password = getpass("Set a password to protect your private key: ").encode()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE
    )

    public_key = private_key.public_key()

    # Store encrypted private key
    with open(KEY_DIR / "private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            )
        )

    # Store public key
    with open(KEY_DIR / "public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("[+] RSA key pair generated and private key encrypted.")
