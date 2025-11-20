from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import hashlib
import hmac
import struct
from typing import ClassVar


class HashlibSHA256:
    digest_size: ClassVar[int] = hashlib.sha256().digest_size
    block_size: ClassVar[int] = hashlib.sha256().block_size

    @staticmethod
    def new(data: bytes | None = None):
        h = hashlib.sha256()
        if data:
            h.update(data)
        return h


# 1. Генерація RSA-ключів


def generate_rsa_keys(bits=2048):
    key = RSA.generate(bits)
    priv_pem = key.export_key("PEM")
    pub_pem = key.publickey().export_key("PEM")
    return priv_pem, pub_pem


# 2. Гібридне шифрування


def hybrid_encrypt(plaintext: bytes, pub_pem: bytes) -> bytes:
    # 2.1. Завантажити публічний ключ та створити RSA-OAEP шифр
    rsa_key = RSA.import_key(pub_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=HashlibSHA256)

    # 2.2. Згенерувати AES-ключ та IV
    aes_key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)  # 128-бітний IV

    # 2.3. AES-CBC + PKCS#7 padding
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = aes_cipher.encrypt(padded)

    # 2.4. RSA-OAEP шифрує AES-ключ
    enc_key = rsa_cipher.encrypt(aes_key)

    # 2.5. Згенерувати окремий ключ для HMAC
    hmac_key = get_random_bytes(32)

    # 2.6. HMAC-SHA256(enc_key || iv || ciphertext)
    tag = hmac.new(hmac_key, enc_key + iv + ciphertext, hashlib.sha256).digest()

    # 2.7. Пакуємо все в один blob:
    # [2 байти: len(enc_key)][enc_key][32 байти: hmac_key][16 байт: iv][ciphertext][32 байти: tag]
    blob = struct.pack(">H", len(enc_key)) + enc_key + hmac_key + iv + ciphertext + tag
    return blob


# 3. Гібридне розшифрування


def hybrid_decrypt(blob: bytes, priv_pem: bytes) -> bytes:
    # 3.1. Розпаковуємо blob
    offset = 0
    (enc_key_len,) = struct.unpack(">H", blob[offset : offset + 2])
    offset += 2

    enc_key = blob[offset : offset + enc_key_len]
    offset += enc_key_len

    hmac_key = blob[offset : offset + 32]
    offset += 32

    iv = blob[offset : offset + 16]
    offset += 16

    tag = blob[-32:]
    ciphertext = blob[offset:-32]

    # 3.2. Перевірка HMAC-SHA256
    calc_tag = hmac.new(hmac_key, enc_key + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(calc_tag, tag):
        raise ValueError("HMAC verification failed")

    # 3.3. Розшифрування AES-ключа RSA-OAEP
    rsa_key = RSA.import_key(priv_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=HashlibSHA256)
    aes_key = rsa_cipher.decrypt(enc_key)

    # 3.4. AES-CBC розшифрування + видалення PKCS#7 padding
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    padded = aes_cipher.decrypt(ciphertext)

    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Невірний padding")

    plaintext = padded[:-pad_len]
    return plaintext


# 4. Контрольний приклад

if __name__ == "__main__":
    priv_pem, pub_pem = generate_rsa_keys(2048)

    message = (
        b"Hybrid cryptosystem test under Linux with PyCryptodome.\n"
        b"AES-256-CBC + RSA-2048-OAEP + HMAC-SHA256."
    )

    blob = hybrid_encrypt(message, pub_pem)
    recovered = hybrid_decrypt(blob, priv_pem)

    print("Original :", message)
    print("Recovered:", recovered)
    print("OK:", message == recovered)
