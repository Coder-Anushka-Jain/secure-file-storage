from crypto.file_crypto import encrypt_file, decrypt_file

if __name__ == "__main__":
    encrypt_file("test.txt", "test.txt.enc")
    decrypt_file("test.txt.enc", "test_decrypted.txt")
