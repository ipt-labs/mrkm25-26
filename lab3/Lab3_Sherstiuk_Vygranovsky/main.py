from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS


def generate_keys(private_key_file="ecc_private.pem", public_key_file="ecc_public.pem"):
    key = ECC.generate(curve="P-256")

    private_pem = key.export_key(format="PEM")
    public_pem = key.public_key().export_key(format="PEM")

    with open(private_key_file, "wt") as f:
        f.write(private_pem)

    with open(public_key_file, "wt") as f:
        f.write(public_pem)

    print("Ключі згенеровано і збережено у файли:")
    print(f"- Приватний ключ: {private_key_file}")
    print(f"- Публічний ключ: {public_key_file}")


def load_private_key(private_key_file="ecc_private.pem"):
    with open(private_key_file, "rt") as f:
        private_pem = f.read()
    return ECC.import_key(private_pem)


def load_public_key(public_key_file="ecc_public.pem"):
    with open(public_key_file, "rt") as f:
        public_pem = f.read()
    return ECC.import_key(public_pem)


def sign_message(message: bytes, private_key: ECC.EccKey) -> bytes:
    hash_obj = SHA256.new(message)
    signer = DSS.new(private_key, "fips-186-3")
    signature = signer.sign(hash_obj)
    return signature


def verify_signature(message: bytes, signature: bytes, public_key: ECC.EccKey) -> bool:
    hash_obj = SHA256.new(message)
    verifier = DSS.new(public_key, "fips-186-3")
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False


def demo():
    generate_keys()

    priv_key = load_private_key()
    pub_key = load_public_key()

    message_str = "Це тестове повідомлення для підпису ECDSA"
    message = message_str.encode("utf-8")
    print("\nПовідомлення:", message_str)

    signature = sign_message(message, priv_key)
    print("\nПідпис (у hex):", signature.hex())

    ok = verify_signature(message, signature, pub_key)
    print("\nПеревірка правильного підпису:", "успішна" if ok else "неуспішна")

    fake_message = "Це вже інше повідомлення".encode("utf-8")
    ok_fake = verify_signature(fake_message, signature, pub_key)
    print("Перевірка підпису з підробленим повідомленням:", "успішна" if ok_fake else "неуспішна")


if __name__ == "__main__":
    demo()
