from pathlib import Path
import json
import base64

from crypto.aes_utils import generate_aes_key, encrypt_data
from crypto.hybrid_utils import encrypt_aes_key


def encrypt_file(input_file: str, output_file: str):
    """
    Encrypts a file using hybrid encryption (AES-GCM + RSA).
    """

    input_path = Path(input_file)
    output_path = Path(output_file)

    # 1️⃣ Read file bytes
    plaintext = input_path.read_bytes()

    # 2️⃣ Generate AES session key
    aes_key = generate_aes_key()

    # 3️⃣ Encrypt file using AES-GCM
    nonce, ciphertext = encrypt_data(plaintext, aes_key)

    # 4️⃣ Encrypt AES key using RSA public key
    encrypted_aes_key = encrypt_aes_key(aes_key)

    # 5️⃣ Store everything together (Base64 for safe storage)
    encrypted_bundle = {
        "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

    output_path.write_text(json.dumps(encrypted_bundle))

    print(f"[+] File encrypted successfully: {output_file}")
