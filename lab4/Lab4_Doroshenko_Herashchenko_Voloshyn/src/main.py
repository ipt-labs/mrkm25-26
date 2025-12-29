from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import os


def generate_keys():
    print("[*] Generating ECC keys (P-256)...")
    key = ECC.generate(curve="P-256")

    with open("private_key.pem", "wt") as f:
        f.write(key.export_key(format="PEM"))

    with open("public_key.pem", "wt") as f:
        f.write(key.public_key().export_key(format="PEM"))

    print("[+] Keys saved to 'private_key.pem' and 'public_key.pem'")


def sign_message(message_bytes):
    with open("private_key.pem", "rt") as f:
        key = ECC.import_key(f.read())

    h = SHA256.new(message_bytes)

    signer = DSS.new(key, "fips-186-3")
    signature = signer.sign(h)

    print(f"[+] Message signed. Hash: {h.hexdigest()}")
    return signature


def verify_signature(message_bytes, signature):
    with open("public_key.pem", "rt") as f:
        key = ECC.import_key(f.read())

    h = SHA256.new(message_bytes)
    verifier = DSS.new(key, "fips-186-3")
    try:
        verifier.verify(h, signature)
        print("[SUCCESS] Signature is valid. Authorship confirmed.")
        return True
    except ValueError:
        print("[ERROR] Signature is invalid! Message modified or incorrect key.")
        return False


if __name__ == "__main__":
    generate_keys()

    input("\npress any key")

    msg = b"Hello world!"
    print(f"\n[*] Message: {msg}")
    signature = sign_message(msg)

    print("\n[*] Verifying original message...")
    verify_signature(msg, signature)

    print("\n[*] Attempting to verify modified message...")
    fake_msg = b"Goodbye world!"
    verify_signature(fake_msg, signature)
