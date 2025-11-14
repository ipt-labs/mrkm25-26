import os
import sys
import time
import tempfile
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

# --- CONFIGURATION ---
NUM_TESTS = 10 

AES_KEY_SIZE = 32 # 256 bits
AES_BLOCK_SIZE = 16 
CHUNK_SIZE = 64 * 1024 # 64KB

RSA_KEY_SIZE = 2048
RSA_DATA_SIZE = 32 # 32-byte session key

# --- Symmetric Test Function ---
def run_aes_test(input_filepath, temp_enc_path, key, iv):
    """Performs AES Enc/Dec streaming on file and returns (enc_time, dec_time)."""
    cipher_enc = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    start_time_enc = time.perf_counter()
    
    with open(input_filepath, 'rb') as f_in, open(temp_enc_path, 'wb') as f_out:
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk: break
            f_out.write(cipher_enc.encrypt(chunk))
            
    end_time_enc = time.perf_counter()
    enc_time = end_time_enc - start_time_enc
    
    cipher_dec = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    start_time_dec = time.perf_counter()
    
    with open(temp_enc_path, 'rb') as f_in:
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk: break
            cipher_dec.decrypt(chunk) 
            
    end_time_dec = time.perf_counter()
    dec_time = end_time_dec - start_time_dec
    
    return enc_time, dec_time

# --- Core Asymmetric Test Function (32 Bytes Session Key) ---
def run_rsa_test(data_to_encrypt):
    """Performs RSA KeyGen, Enc, and Dec on 32-byte session key."""
    
    # 1. KEY GENERATION
    start_time_keygen = time.perf_counter()
    key = RSA.generate(RSA_KEY_SIZE)
    public_key = key.publickey()
    end_time_keygen = time.perf_counter()
    keygen_time = end_time_keygen - start_time_keygen
    
    # 2. ENCRYPTION
    cipher_rsa = PKCS1_OAEP.new(public_key)
    start_time_enc = time.perf_counter()
    encrypted_data = cipher_rsa.encrypt(data_to_encrypt)
    end_time_enc = time.perf_counter()
    enc_time = end_time_enc - start_time_enc
    
    # 3. DECRYPTION
    decryptor_rsa = PKCS1_OAEP.new(key)
    start_time_dec = time.perf_counter()
    decryptor_rsa.decrypt(encrypted_data)
    end_time_dec = time.perf_counter()
    dec_time = end_time_dec - start_time_dec
    
    return keygen_time, enc_time, dec_time

# --- Hashing Test Function ---
def run_hashing_test(input_filepath):
    """Performs SHA-256 hashing on the file and returns hash_time."""
    
    hasher = SHA256.new()
    start_time = time.perf_counter()
    
    with open(input_filepath, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk: break
            hasher.update(chunk)
            
    end_time = time.perf_counter()
    hash_time = end_time - start_time
    
    return hash_time

# --- Main Benchmarking ---
def run_benchmarks(input_file):
    if not os.path.exists(input_file):
        print(f"Error: Input file not found at {input_file}")
        sys.exit(1)

    file_size_bytes = os.path.getsize(input_file)
    if file_size_bytes % AES_BLOCK_SIZE != 0:
        print("ERROR: File size is not a multiple of 16 bytes for AES. Cannot run without padding.")
        sys.exit(1)

    print(f"--- PyCryptodome AES|RSA|SHA256 Benchmark ---")
    print(f"Input File: {os.path.basename(input_file)}")
    print(f"File Size: {file_size_bytes / (1024*1024):.2f} MB")
    print(f"Number of Runs: {NUM_TESTS}")
    print("-" * 60)


    temp_fd, temp_enc_path = tempfile.mkstemp()
    os.close(temp_fd)
    rsa_session_key = get_random_bytes(RSA_DATA_SIZE)
    
    aes_enc_times, aes_dec_times = [], []
    rsa_keygen_times, rsa_enc_times, rsa_dec_times = [], [], []
    hash_times = []

    for i in range(1, NUM_TESTS + 1):
        aes_key = get_random_bytes(AES_KEY_SIZE)
        aes_iv = get_random_bytes(AES_BLOCK_SIZE)

        # 1. AES
        enc_time, dec_time = run_aes_test(input_file, temp_enc_path, aes_key, aes_iv)
        aes_enc_times.append(enc_time); aes_dec_times.append(dec_time)
        print(f"Run {i}/{NUM_TESTS}: AES Enc={enc_time:.4f}s, Dec={dec_time:.4f}s")
            
        # 2. RSA
        keygen_time, enc_time, dec_time = run_rsa_test(rsa_session_key)
        rsa_keygen_times.append(keygen_time); rsa_enc_times.append(enc_time); rsa_dec_times.append(dec_time)
        print(f"Run {i}/{NUM_TESTS}: RSA Gen={keygen_time:.6f}s, Enc={enc_time:.6f}s, Dec={dec_time:.6f}s")

        # 3. SHA-256
        hash_time = run_hashing_test(input_file)
        hash_times.append(hash_time)
        print(f"Run {i}/{NUM_TESTS}: SHA-256 Hash={hash_time:.4f}s")
            
    os.remove(temp_enc_path)

    print("\n" + "="*60)
    print("### FINAL AVERAGE TIME RESULTS (10 Runs) ###")
    print("="*60)
    
    print(f"**1. Symmetric Encryption (AES-256 CBC) on 1GB**")
    print(f"   Average Encryption Time: **{sum(aes_enc_times) / len(aes_enc_times):.4f} seconds**")
    print(f"   Average Decryption Time: **{sum(aes_dec_times) / len(aes_dec_times):.4f} seconds**")
    print("-" * 60)

    print(f"**2. Asymmetric Encryption (RSA-2048) on 32 Bytes (Key Exchange)**")
    print(f"   Average Key Generation Time: **{sum(rsa_keygen_times) / len(rsa_keygen_times):.6f} seconds**")
    print(f"   Average Encryption Time:   **{sum(rsa_enc_times) / len(rsa_enc_times):.6f} seconds**")
    print(f"   Average Decryption Time:   **{sum(rsa_dec_times) / len(rsa_dec_times):.6f} seconds**")
    print("-" * 60)

    print(f"**3. Hashing (SHA-256) on 1GB**")
    print(f"   Average Hashing Time: **{sum(hash_times) / len(hash_times):.4f} seconds**")
    print("="*60)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pycryptodome_final_benchmark.py <path_to_input_file_1GB>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    run_benchmarks(input_file)
