from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC 
import struct

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Wrong block size for PKCS#7 unpad")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("wrong padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("wrong padding")
    return data[:-pad_len]

def generate_rsa_keys(bits: int = 2048):
    key = RSA.generate(bits)
    priv_pem = key.export_key(format='PEM')
    pub_pem = key.publickey().export_key(format='PEM')
    return priv_pem, pub_pem

def hybrid_encrypt(plaintext: bytes, pub_pem: bytes) -> bytes:

    pub_key = RSA.import_key(pub_pem)
    rsa_cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)

    aes_key = get_random_bytes(32) 
    iv = get_random_bytes(16)      

    aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    padded = pkcs7_pad(plaintext, 16)
    ciphertext = aes.encrypt(padded)

    enc_key = rsa_cipher.encrypt(aes_key) 

    hmac_key = get_random_bytes(32)
    h = HMAC.new(hmac_key, enc_key + iv + ciphertext, digestmod=SHA256)
    tag = h.digest()

    blob = struct.pack(">H", len(enc_key)) + enc_key + hmac_key + iv + ciphertext + tag
    return blob

def hybrid_decrypt(blob: bytes, priv_pem: bytes) -> bytes:
    if len(blob) < 2:
        raise ValueError("Wrong continer format")
    enc_len = struct.unpack(">H", blob[:2])[0]
    off = 2
    enc_key = blob[off:off+enc_len]; off += enc_len
    hmac_key = blob[off:off+32]; off += 32
    iv = blob[off:off+16]; off += 16
    
    tag_size = SHA256.digest_size
    ciphertext = blob[off:-tag_size]
    tag = blob[-tag_size:]

    h = HMAC.new(hmac_key, enc_key + iv + ciphertext, digestmod=SHA256)
    try:
        h.verify(tag)
    except ValueError:
        raise ValueError("HMAC verification failed: Data was changed!")

    priv_key = RSA.import_key(priv_pem)
    rsa_cipher = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    aes_key = rsa_cipher.decrypt(enc_key)

    aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    padded = aes.decrypt(ciphertext)
    plaintext = pkcs7_unpad(padded, 16)
    return plaintext

if __name__ == "__main__":
    print("Key generation...")
    priv_pem, pub_pem = generate_rsa_keys(2048)
    
    message = (
        b"Lab1 message for encoding.\n"
        b"AES-256-CBC + RSA-OAEP(SHA-256) + HMAC-SHA256."
    )
    
    print("Cyphering...")
    blob = hybrid_encrypt(message, pub_pem)
    
    print("Decyphering...")
    recovered = hybrid_decrypt(blob, priv_pem)
    
    print("-" * 20)
    print("Result:", recovered.decode())
    print("Integrity check OK:", recovered == message)