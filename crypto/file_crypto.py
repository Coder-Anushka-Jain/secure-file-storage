from pathlib import Path
import json
import base64

from crypto.aes_utils import generate_aes_key, encrypt_data, decrypt_data
from crypto.hybrid_utils import encrypt_aes_key, decrypt_aes_key



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



def decrypt_file(input_file: str, output_file: str):
    """
    Decrypts a file encrypted using hybrid encryption.
    """

    input_path = Path(input_file)
    output_path = Path(output_file)

    # 1️⃣ Load encrypted bundle
    encrypted_bundle = json.loads(input_path.read_text())

    encrypted_aes_key = base64.b64decode(encrypted_bundle["encrypted_key"])
    nonce = base64.b64decode(encrypted_bundle["nonce"])
    ciphertext = base64.b64decode(encrypted_bundle["ciphertext"])

    # 2️⃣ Decrypt AES key using RSA private key
    aes_key = decrypt_aes_key(encrypted_aes_key)

    # 3️⃣ Decrypt file using AES-GCM
    plaintext = decrypt_data(nonce, ciphertext, aes_key)

    # 4️⃣ Write original file back
    output_path.write_bytes(plaintext)

    print(f"[+] File decrypted successfully: {output_file}")

