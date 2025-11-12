#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# Load the private key
try:
    with open("private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
except FileNotFoundError:
    print("Error: private.pem not found.")
    exit()

# Load the encrypted session key
try:
    with open("encrypted_session.bin", "rb") as f:
        encrypted_session_key = f.read()
except FileNotFoundError:
    print("Error: encrypted_session.bin not found.")
    exit()

# Decrypt the session key using the private key
try:
    decrypt_cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_session_key = decrypt_cipher_rsa.decrypt(encrypted_session_key)
    print(
        f"Recovered Session Key: {binascii.hexlify(decrypted_session_key).decode('utf-8')}"
    )

except (ValueError, TypeError):
    print("Decryption failed.")
