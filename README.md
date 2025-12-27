# Secure File Storage System 

A secure file storage tool that encrypts files using **AES-GCM** and protects encryption keys using **RSA-OAEP**.  
Designed with real-world cryptographic best practices and a clear threat model.

---

## Features

- Hybrid encryption (AES-GCM + RSA-OAEP)
- Password-protected RSA private key
- Integrity and authenticity via AES-GCM
- Command-line interface (CLI)
- Clean separation of cryptographic layers

---

## Architecture Overview
Plain File
↓
AES-GCM Encryption (random key per file)
↓
Encrypted File + Nonce
↓
RSA-OAEP Encryption of AES Key
↓
Encrypted File Bundle (.enc)

---

## Cryptographic Choices

### AES-GCM
- Fast, secure symmetric encryption
- Provides confidentiality, integrity, and authentication
- Uses a random 96-bit nonce per encryption

### RSA-OAEP
- Secure asymmetric encryption
- Used only to encrypt AES keys
- Private key encrypted at rest using a password

---

##  How to Run

### Encrypt a file
```bash
python -m cli.main encrypt file.txt

Decrypt a file
python -m cli.main decrypt file.txt.enc




