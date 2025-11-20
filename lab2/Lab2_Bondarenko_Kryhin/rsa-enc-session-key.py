#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import binascii

# Generate a new random session key
session_key = get_random_bytes(32)
print(f"New Session Key: {binascii.hexlify(session_key).decode('utf-8')}")

# Load the recipient's public key
try:
    with open("public.pem", "rb") as f:
        public_key = RSA.import_key(f.read())
except FileNotFoundError:
    print("Error: public.pem not found.")
    exit()

# Encrypt the session key using the public key and PKCS#1 OAEP
cipher_rsa = PKCS1_OAEP.new(public_key)
encrypted_session_key = cipher_rsa.encrypt(session_key)

# Save the encrypted session key to a file
with open("encrypted_session.bin", "wb") as f:
    f.write(encrypted_session_key)

print("Successfully encrypted session key and saved to encrypted_session.bin")
