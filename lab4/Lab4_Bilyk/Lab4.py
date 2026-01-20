from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from base64 import b64encode
import os
import signal
import time


def generate_keys(curve_name: str = "P-256"):
    private_key = ECC.generate(curve=curve_name)
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(private_key: ECC.EccKey, message: bytes) -> bytes:
    h = SHA256.new(message)
    signer = DSS.new(private_key, mode="fips-186-3")
    return signer.sign(h)


def verify_signature(public_key: ECC.EccKey, message: bytes, signature: bytes) -> bool:
    h = SHA256.new(message)
    verifier = DSS.new(public_key, mode="fips-186-3")
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


def export_keys(private_key: ECC.EccKey, public_key: ECC.EccKey):
    private_pem = private_key.export_key(format="PEM", use_pkcs8=True)
    public_pem = public_key.export_key(format="PEM")  # SPKI
    return private_pem, public_pem


def hold_sigstop(private_key):
  
    pid = os.getpid()
    d_value = int(private_key.d)

    print(f"\nPID = {pid}")
    print(f"d = {hex(d_value)}")
    print(f"Stopped\n", flush=True)
    os.kill(pid, signal.SIGSTOP)


def main():
    message = b"Lab: ECDSA signing example (Linux, Python)."

    private_key, public_key = generate_keys(curve_name="P-256")

    hold_sigstop(private_key)


    signature = sign_message(private_key, message)
    ok = verify_signature(public_key, message, signature)

    tampered_message = b"Lab: ECDSA signing example (Linux, Python)!"
    ok_tampered = verify_signature(public_key, tampered_message, signature)

    priv_pem, pub_pem = export_keys(private_key, public_key)

    print("\n[TEST 1] Original message integrity check:")
    print(f"Message: {message!r}")
    print(f"Signature (Base64): {b64encode(signature).decode()}")
    print(f"Verification result: {ok}")
    print("Status:", "PASSED" if ok else "FAILED")

    print("\n[TEST 2] Tampered message integrity check:")
    print(f"Tampered message: {tampered_message!r}")
    print(f"Verification result: {ok_tampered}")
    if not ok_tampered:
        print("Status: FAILED — integrity violation detected (expected).")


    print("\n[INFO] Done.")


if __name__ == "__main__":
    main()
