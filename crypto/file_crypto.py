from pathlib import Path
import json
import base64

from crypto.aes_utils import generate_aes_key, encrypt_data, decrypt_data
from crypto.hybrid_utils import encrypt_aes_key, decrypt_aes_key
from cryptography.exceptions import InvalidTag


def encrypt_file(input_file: str, output_file: str):
    input_path = Path(input_file)
    output_path = Path(output_file)

    plaintext = input_path.read_bytes()
    aes_key = generate_aes_key()

    version = 1

    # 🔐 AAD binds version + filename
    aad = f"{version}:{input_path.name}".encode()

    nonce, ciphertext = encrypt_data(
        plaintext,
        aes_key,
        aad=aad
    )

    encrypted_aes_key = encrypt_aes_key(aes_key)

    encrypted_bundle = {
        "version": version,
        "filename": input_path.name,
        "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

    output_path.write_text(json.dumps(encrypted_bundle))
    print(f"[+] File encrypted successfully: {output_file}")







def decrypt_file(input_file: str, output_file: str):
    input_path = Path(input_file)
    output_path = Path(output_file)

    try:
        encrypted_bundle = json.loads(input_path.read_text())

        version = encrypted_bundle.get("version")
        if version != 1:
            raise ValueError("Unsupported encrypted file version")

        encrypted_aes_key = base64.b64decode(encrypted_bundle["encrypted_key"])
        nonce = base64.b64decode(encrypted_bundle["nonce"])
        ciphertext = base64.b64decode(encrypted_bundle["ciphertext"])

        aad = f"{version}:{encrypted_bundle['filename']}".encode()

        aes_key = decrypt_aes_key(encrypted_aes_key)

        plaintext = decrypt_data(
            nonce,
            ciphertext,
            aes_key,
            aad=aad
        )

        output_path.write_bytes(plaintext)
        print(f"[+] File decrypted successfully: {output_file}")

    except InvalidTag:
        print("Decryption failed: file has been tampered with or wrong password used")

    except KeyError:
        print("Invalid encrypted file format")

    except ValueError as e:
        print(f"{str(e)}")

    except Exception:
        print("Decryption failed due to an unexpected error")
