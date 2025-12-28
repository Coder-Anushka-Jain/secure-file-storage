import argparse
import sys
from pathlib import Path

from crypto.file_crypto import encrypt_file, decrypt_file


def main():
    parser = argparse.ArgumentParser(
        description="Secure File Storage using Hybrid Encryption (AES-GCM + RSA-OAEP)"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("input_file", help="Path to file to encrypt")

    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("input_file", help="Path to .enc file to decrypt")

    args = parser.parse_args()
    input_path = Path(args.input_file)

    # Common validation
    if not input_path.exists():
        print("❌ Error: file does not exist")
        sys.exit(1)

    # Encrypt flow
    if args.command == "encrypt":
        output_file = input_path.name + ".enc"
        encrypt_file(input_path, output_file)

    # Decrypt flow
    elif args.command == "decrypt":
        if not input_path.name.endswith(".enc"):
            print("❌ Error: encrypted file must have .enc extension")
            sys.exit(1)

        output_file = input_path.stem + "_decrypted"
        decrypt_file(input_path, output_file)


if __name__ == "__main__":
    main()
