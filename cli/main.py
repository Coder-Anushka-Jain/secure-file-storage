from crypto.aes_utils import generate_aes_key
from crypto.hybrid_utils import encrypt_aes_key, decrypt_aes_key

if __name__ == "__main__":
    aes_key = generate_aes_key()
    print("Original AES key:", aes_key)

    encrypted_key = encrypt_aes_key(aes_key)
    print("Encrypted AES key:", encrypted_key)

    decrypted_key = decrypt_aes_key(encrypted_key)
    print("Decrypted AES key:", decrypted_key)

    assert aes_key == decrypted_key
    print("SUCCESS: AES key recovered correctly")
