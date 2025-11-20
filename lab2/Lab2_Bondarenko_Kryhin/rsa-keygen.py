#!/usr/bin/env python3
from Crypto.PublicKey import RSA

print("Generating RSA 2048-bit key pair...")
key = RSA.generate(2048)

# Generate and save the private key
private_key = key.export_key()
with open("private.pem", "wb") as f:
    f.write(private_key)

# Generate and save the public key
public_key = key.publickey().export_key()
with open("public.pem", "wb") as f:
    f.write(public_key)

print("Saved private.pem and public.pem")