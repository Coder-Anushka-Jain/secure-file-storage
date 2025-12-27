from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path


KEY_SIZE = 2048
KEY_DIR = Path("keys")


def generate_rsa_keys():
    """
    Generates an RSA key pair and stores them on disk.
    Private key is currently stored without encryption
    (will be encrypted in next phase).
    """

    KEY_DIR.mkdir(exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE
    )

    public_key = private_key.public_key()

    # Store private key
    with open(KEY_DIR / "private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
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

    print("[+] RSA key pair generated successfully.")
