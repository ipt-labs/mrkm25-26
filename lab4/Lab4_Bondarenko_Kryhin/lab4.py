import os
import getpass
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def generate_and_store_key():
    print("\n--- 1. Key Generation and Export (NIST P-256, PKCS#8, SHA-512/AES-256) ---")
    
    private_key_file = input("Enter the filename for the encrypted private key (e.g., ecdsa_private.pem): ")
    passphrase_str = getpass.getpass("Enter a secure passphrase for key encryption: ")
    
    passphrase_bytes = passphrase_str.encode('utf-8')
    
    PROTECTION_ALGORITHM_STR = "PBKDF2WithHMAC-SHA512AndAES256-CBC"
    
    # NIST P-256/ECC Standard
    private_key_object = ECC.generate(curve='P-256')
    public_key_object = private_key_object.public_key() # Derive public key
    print("Generated new ECDSA key pair (NIST P-256).")
    
    # PKCS#8 and PKCS#5 Standards (Private Key Export)
    try:
        encrypted_pem_key_str = private_key_object.export_key(
            format='PEM',
            use_pkcs8=True,
            passphrase=passphrase_bytes,
            protection=PROTECTION_ALGORITHM_STR
        )
        
        with open(private_key_file, "w") as f:
            f.write(encrypted_pem_key_str)
        
        print(f"Private key securely stored in {private_key_file} (Encrypted PKCS#8 PEM).")
        
        public_key_file = private_key_file.replace(".pem", ".pub") if ".pem" in private_key_file else private_key_file + ".pub"
        public_pem_str = public_key_object.export_key(format='PEM')
        
        with open(public_key_file, "w") as f:
            f.write(public_pem_str)
            
        print(f"Public key exported to {public_key_file} for distribution.")
        return public_key_object
        
    except Exception as e:
        print(f"Error during key export: {e}")
        return None

def sign_message(public_keys):
    print("\n--- 2. Key Loading and Signing (FIPS 186-4, SHA256) ---")
    
    private_key_file = input("Enter the filename of the encrypted private key to use: ")
    decryption_passphrase_str = getpass.getpass(f"Enter passphrase to decrypt {private_key_file}: ")
    
    decryption_passphrase_bytes = decryption_passphrase_str.encode('utf-8')
    
    # ISO 8859-1 (Latin-1) message encoding
    message_content = input("Enter the content of the message to be signed (will use ISO 8859-1 encoding): ")
    message = message_content.encode('iso-8859-1')
    
    loaded_key = None
    # PKCS#8/PKCS#5 Standard (Import)
    try:
        with open(private_key_file, "r") as f:
            encrypted_key_data_str = f.read()
        
        encrypted_key_data_bytes = encrypted_key_data_str.encode('ascii')
            
        loaded_key = ECC.import_key(encrypted_key_data_bytes, passphrase=decryption_passphrase_bytes) 
        public_key_object = loaded_key.public_key()
        print("Encrypted private key loaded and decrypted successfully.")
    except FileNotFoundError:
        print(f"Error: Private key file {private_key_file} not found.")
        return
    except ValueError as e:
        print(f"Error: Failed to decrypt key. Incorrect passphrase or unsupported protection. Details: {e}")
        return
    except Exception as e:
        print(f"Error loading key: {e}")
        return

    # FIPS 180-4 (SHA-2 Standard)
    message_hash = SHA256.new(message)

    # FIPS 186-4/FIPS 186-3 (DSS Standard Mode)
    try:
        signer = DSS.new(loaded_key, 'fips-186-3')
        digital_signature = signer.sign(message_hash)
        
        print("Message successfully signed.")
        print(f"Signature (hex): {digital_signature.hex()[:60]}...")
        
        public_keys[private_key_file] = (public_key_object, message, digital_signature)

        export_choice = input("Do you want to export the message and signature to files? (y/n): ").strip().lower()
        if export_choice == 'y':
            base_filename = input("Enter a base filename for message/signature (e.g., doc_a): ")
            
            message_file = f"{base_filename}.msg"
            with open(message_file, "wb") as f:
                f.write(message)
            print(f"Message saved to {message_file}.")

            signature_file = f"{base_filename}.sig"
            with open(signature_file, "wb") as f:
                f.write(digital_signature)
            print(f"Signature saved to {signature_file}.")
        
    except Exception as e:
        print(f"Error during signing: {e}")

def display_menu(public_keys):
    print("\n==============================================")
    print("      ECDSA Cryptosystem Protocol Menu")
    print("==============================================")
    print(f"Internally Stored Signatures: {len(public_keys)}")
    print("1. Generate and Securely Store New Private Key (Exports Private/Public Keys)")
    print("2. Sign New Message (Allows Export of Message/Signature)")
    print("3. Verify Signature (Requires Public Key, Message, and Signature Files)")
    print("4. Exit")
    print("----------------------------------------------")

def main_loop():
    public_keys = {} 
    
    while True:
        display_menu(public_keys)
        choice = input("Select an option (1-4): ")
        
        if choice == '1':
            generate_and_store_key() 
        elif choice == '2':
            sign_message(public_keys)
        elif choice == '3':
            print("\n--- 3. Signature Verification ---")

            try:
                public_key_file = input("Enter filename of the public key (.pub file): ")
                message_file = input("Enter filename of the signed message (.msg file): ")
                signature_file = input("Enter filename of the signature (.sig file): ")

                with open(public_key_file, "r") as f:
                    public_key_data_str = f.read()
                public_key = ECC.import_key(public_key_data_str)
                print("Public Key loaded.")

                with open(message_file, "rb") as f:
                    message_to_check = f.read()
                
                with open(signature_file, "rb") as f:
                    digital_signature = f.read()
                
                # FIPS 186-4 Verification Procedure
                verifier_hash = SHA256.new(message_to_check)
                
                verifier = DSS.new(public_key, 'fips-186-3')

                try:
                    verifier.verify(verifier_hash, digital_signature)
                    print("\nRESULT: Signature is **VALID**. Message authenticity and integrity confirmed.")
                except ValueError:
                    print("\nRESULT: Signature is **INVALID**. The message, signature, or key is corrupted/incorrect.")
            
            except FileNotFoundError as e:
                print(f"Error: One of the required files was not found: {e}")
            except Exception as e:
                print(f"Verification Failed due to an unexpected error: {e}")
            

        elif choice == '4':
            print("Exiting protocol. Goodbye.")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main_loop()
