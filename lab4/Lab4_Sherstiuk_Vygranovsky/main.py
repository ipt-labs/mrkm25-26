import os
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

print(f"Target PID: {os.getpid()}")
key = ECC.generate(curve='P-256')
d_value = key.d

print(f"Ключ згенеровано. {hex(d_value)} Чекаємо на команду...")
input("Натисніть Enter, щоб виконати підпис і вийти...")

message = b"Secret data to sign"
h = SHA256.new(message)
signer = DSS.new(key, 'fips-186-3')
signature = signer.sign(h)

print("Підпис виконано. Процес завершується.")