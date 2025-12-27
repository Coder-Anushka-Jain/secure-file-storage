from crypto.aes_utils import generate_aes_key, encrypt_data, decrypt_data

if __name__ == "__main__":
    message = b"this is a super secret message"

    key = generate_aes_key()

    nonce, ciphertext = encrypt_data(message, key)

    decrypted = decrypt_data(nonce, ciphertext, key)

    print("Original :", message)
    print("Encrypted:", ciphertext)
    print("Decrypted:", decrypted)
