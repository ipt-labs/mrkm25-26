#include <iostream>
#include <fstream>
#include <vector>
#include <numeric>
#include <iomanip>
#include <string>
#include <sstream>

extern "C" {
    #include "benchmark.h"
    
    void measure_start_time();
    void measure_end_time();
    void measure_start_mem();
    void measure_end_mem();
    
    extern struct timespec time_start, time_end;
    extern long mem_start, mem_end;
}

#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/oaep.h>
#include <cryptopp/secblock.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;
using namespace std;

// --- CONFIGURATION ---
const int NUM_TESTS = 10;
const size_t AES_KEY_SIZE = 32;
const size_t AES_BLOCK_SIZE = AES::BLOCKSIZE;
const int RSA_KEY_SIZE = 2048;
const size_t RSA_DATA_SIZE = 32;

double calculate_execution_time() {
    return (time_end.tv_sec - time_start.tv_sec) +
           (time_end.tv_nsec - time_start.tv_nsec) / 1e9;
}

struct Metrics {
    double time;
    long mem_delta;
};

template<typename Func>
Metrics measure_op(Func op) {
    measure_start_time();
    measure_start_mem();
    
    op(); // Execute the cryptographic operation
    
    measure_end_time();
    measure_end_mem();
    
    return {
        calculate_execution_time(),
        mem_end - mem_start
    };
}


// --- Symmetric (AES) Test Functions ---

Metrics run_aes_test_enc(const string& input_filepath, const string& temp_enc_path, const SecByteBlock& key, const SecByteBlock& iv) {
    auto op = [&]() {
        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv);
        FileSource fs(input_filepath.c_str(), true, 
                      new StreamTransformationFilter(enc, new FileSink(temp_enc_path.c_str(), false))
        );
    };
    try {
        return measure_op(op);
    } catch (const Exception& e) {
        cerr << "AES Encryption Error: " << e.what() << endl;
        return {0.0, 0};
    }
}

Metrics run_aes_test_dec(const string& temp_enc_path, const SecByteBlock& key, const SecByteBlock& iv) {
    auto op = [&]() {
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv);
        FileSource fs(temp_enc_path.c_str(), true,
                      new StreamTransformationFilter(dec, new FileSink("/dev/null", false))
        );
    };
    try {
        return measure_op(op);
    } catch (const Exception& e) {
        cerr << "AES Decryption Error: " << e.what() << endl;
        return {0.0, 0};
    }
}

// --- Asymmetric (RSA) Test Functions (32 Bytes Session Key) ---

struct RSAResults {
    Metrics keygen;
    Metrics enc;
    Metrics dec;
};

RSAResults run_rsa_test(const SecByteBlock& data_to_encrypt, AutoSeededRandomPool& prng) {
    RSAResults results = {{0.0, 0}, {0.0, 0}, {0.0, 0}};
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    
    results.keygen = measure_op([&]() {
        privateKey.GenerateRandomWithKeySize(prng, RSA_KEY_SIZE);
        publicKey.AssignFrom(privateKey);
    });

    RSAES_OAEP_SHA_Encryptor rsaEnc(publicKey); 
    string ciphertext;
    
    results.enc = measure_op([&]() {
        StringSource ss(data_to_encrypt.data(), data_to_encrypt.size(), true,
                        new PK_EncryptorFilter(prng, rsaEnc, new StringSink(ciphertext))
        );
    });
    
    // re-encrypt for decryption timing if StringSource was consumed
    ciphertext.clear();
    StringSource ss1(data_to_encrypt.data(), data_to_encrypt.size(), true,
                    new PK_EncryptorFilter(prng, rsaEnc, new StringSink(ciphertext))
    );
    
    RSAES_OAEP_SHA_Decryptor rsaDec(privateKey); 
    
    results.dec = measure_op([&]() {
        string recovered;
        StringSource ss2(ciphertext, true,
                         new PK_DecryptorFilter(prng, rsaDec, new StringSink(recovered))
        );
    });
    
    return results;
}

// --- Hashing Test Function ---

Metrics run_hashing_test(const string& input_filepath) {
    auto op = [&]() {
        SHA256 hash;
        FileSource fs(input_filepath.c_str(), true, 
                      new HashFilter(hash, new FileSink("/dev/null"))
        );
    };
    try {
        return measure_op(op);
    } catch (const Exception& e) {
        cerr << "Hashing Error: " << e.what() << endl;
        return {0.0, 0};
    }
}



int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <path_to_input_file_1GB>" << endl;
        return 1;
    }

    string input_file = argv[1];
    if (!ifstream(input_file).good()) {
        cerr << "Error: Input file not found at " << input_file << endl;
        return 1;
    }
    
    streampos fileSize;
    ifstream file(input_file, ios::binary | ios::ate);
    fileSize = file.tellg();
    file.close();

    if (fileSize % AES_BLOCK_SIZE != 0) {
        cerr << "ERROR: File size is not a multiple of 16 bytes for AES. Cannot run without padding." << endl;
        return 1;
    }


    AutoSeededRandomPool prng;
    string temp_enc_path = "cryptopp_temp_enc.bin";
    SecByteBlock rsa_session_key(RSA_DATA_SIZE);
    prng.GenerateBlock(rsa_session_key, rsa_session_key.size());

    vector<double> aes_enc_times, aes_dec_times;
    vector<double> rsa_keygen_times, rsa_enc_times, rsa_dec_times;
    vector<double> hash_times;

    cout << "--- Crypto++ Comprehensive Benchmark ---" << endl;
    cout << "Input File: " << input_file << endl;
    cout << "File Size: " << fixed << setprecision(2) << (double)fileSize / (1024*1024) << " MB" << endl;
    cout << "Number of Runs: " << NUM_TESTS << endl;
    cout << string(100, '-') << endl;
    cout << "| Run | AES Enc (s) | AES Dec (s) | RSA Gen (s) | RSA Enc (s) | RSA Dec (s) | SHA-256 (s) | Memory Delta (KB) |" << endl;
    cout << string(100, '=') << endl;


    // --- TESTS ---
    for (int i = 1; i <= NUM_TESTS; ++i) {
        SecByteBlock aes_key(AES_KEY_SIZE), aes_iv(AES_BLOCK_SIZE);
        prng.GenerateBlock(aes_key, aes_key.size());
        prng.GenerateBlock(aes_iv, aes_iv.size());
        
        // 1. AES (Symmetric Bulk)
        Metrics aes_enc = run_aes_test_enc(input_file, temp_enc_path, aes_key, aes_iv);
        Metrics aes_dec = run_aes_test_dec(temp_enc_path, aes_key, aes_iv);
        aes_enc_times.push_back(aes_enc.time);
        aes_dec_times.push_back(aes_dec.time);
        
        // 2. RSA (Asymmetric Small Data)
        RSAResults rsa = run_rsa_test(rsa_session_key, prng);
        rsa_keygen_times.push_back(rsa.keygen.time);
        rsa_enc_times.push_back(rsa.enc.time);
        rsa_dec_times.push_back(rsa.dec.time);

        // 3. SHA-256 (Bulk)
        Metrics hash_metrics = run_hashing_test(input_file);
        hash_times.push_back(hash_metrics.time);
        
        long total_mem_delta = aes_enc.mem_delta + aes_dec.mem_delta + 
                               rsa.keygen.mem_delta + rsa.enc.mem_delta + 
                               rsa.dec.mem_delta + hash_metrics.mem_delta;
        
        cout << "| " << setw(3) << i 
             << " | " << fixed << setprecision(4) << setw(11) << aes_enc.time
             << " | " << fixed << setprecision(4) << setw(11) << aes_dec.time
             << " | " << fixed << setprecision(6) << setw(11) << rsa.keygen.time
             << " | " << fixed << setprecision(6) << setw(11) << rsa.enc.time
             << " | " << fixed << setprecision(6) << setw(11) << rsa.dec.time
             << " | " << fixed << setprecision(4) << setw(11) << hash_metrics.time
             << " | " << setw(16) << total_mem_delta << " |" << endl;
    }
    
    remove(temp_enc_path.c_str());
    cout << string(100, '=') << endl;


    auto avg = [](const vector<double>& v) {
        if (v.empty()) return 0.0;
        return accumulate(v.begin(), v.end(), 0.0) / v.size();
    };
    
    cout << "\n" << string(60, '=') << endl;
    cout << "### FINAL AVERAGE TIME RESULTS (10 Runs) ###" << endl;
    cout << string(60, '=') << endl;
    
    // AES Results
    cout << "**1. Symmetric Encryption (AES-256 CBC) on 1GB**" << endl;
    cout << "   Average Encryption Time: **" << fixed << setprecision(4) << avg(aes_enc_times) << " seconds**" << endl;
    cout << "   Average Decryption Time: **" << fixed << setprecision(4) << avg(aes_dec_times) << " seconds**" << endl;
    cout << string(60, '-') << endl;

    // RSA Results
    cout << "**2. Asymmetric Encryption (RSA-2048) on 32 Bytes (Key Exchange)**" << endl;
    cout << "   Average Key Generation Time: **" << fixed << setprecision(6) << avg(rsa_keygen_times) << " seconds**" << endl;
    cout << "   Average Encryption Time:   **" << fixed << setprecision(6) << avg(rsa_enc_times) << " seconds**" << endl;
    cout << "   Average Decryption Time:   **" << fixed << setprecision(6) << avg(rsa_dec_times) << " seconds**" << endl;
    cout << string(60, '-') << endl;

    // Hashing Results
    cout << "**3. Hashing (SHA-256) on 1GB**" << endl;
    cout << "   Average Hashing Time: **" << fixed << setprecision(4) << avg(hash_times) << " seconds**" << endl;
    cout << string(60, '=') << endl;

    return 0;
}
