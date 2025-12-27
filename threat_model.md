# Threat Model – Secure File Storage System

## 🎯 Assets
- User files
- AES session keys
- RSA private key
- User password protecting private key

---

## ⚠️ Threats
- Unauthorized access to encrypted files
- Tampering with encrypted data
- Theft of storage medium
- Brute-force attacks on passwords

---

## 🛡️ Mitigations
- AES-GCM provides confidentiality and integrity
- RSA-OAEP securely encrypts AES keys
- RSA private key encrypted at rest using password-based encryption
- Tampering detected automatically during decryption

---

## 🚫 Out of Scope
- Malware on user’s system
- Keylogging attacks
- Weak user passwords
- Side-channel attacks

---

## ✅ Assumptions
- Cryptographic primitives are implemented correctly by libraries
- User chooses a strong password
- System environment is trusted
