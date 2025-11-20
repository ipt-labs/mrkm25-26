#!/usr/bin/env python3

import sys
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii

KEY_SIZE = 32
NONCE_SIZE = 16
TAG_SIZE = 16


def print_usage():
    """Prints the script's usage instructions."""
    print("[*] Usage: python script.py <filepath> [mode: enc/dec]")
    sys.exit(1)


def encrypt_file(input_file, key):
    """Encrypts a file using AES-256 GCM."""
    output_file = input_file + ".enc"

    try:
        with open(input_file, "rb") as f:
            plaintext = f.read()
    except FileNotFoundError:
        print(f"Error: Input file not found: {input_file}")
        return
    except IOError as e:
        print(f"Error reading file: {e}")
        return

    # Use AES-GCM
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    try:
        with open(output_file, "wb") as f:
            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)
        print(f"File encrypted successfully: {output_file}")
    except IOError as e:
        print(f"Error writing to output file: {e}")


def decrypt_file(input_file, key):
    """Decrypts a file using AES-256 GCM."""

    # Derive output path (e.g., file.txt.enc -> file.txt.dec)
    base_name = os.path.splitext(input_file)[0]
    output_file = base_name + ".dec"

    try:
        with open(input_file, "rb") as f:
            nonce = f.read(NONCE_SIZE)
            tag = f.read(TAG_SIZE)
            ciphertext = f.read()

            if len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE:
                print("Error: File format is invalid or corrupted.")
                return

    except FileNotFoundError:
        print(f"Error: Input file not found: {input_file}")
        return
    except IOError as e:
        print(f"Error reading file: {e}")
        return

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_file, "wb") as f:
            f.write(plaintext)

        print(f"File decrypted successfully: {output_file}")

    except (ValueError, KeyError) as e:
        print("Decryption failed: Key is incorrect or file is corrupted.")


def get_key_from_user():
    """Prompts user for a hex key and converts it to bytes."""
    hex_key = input(f"Enter {KEY_SIZE*2}-char hex key: ").strip()
    try:
        key = binascii.unhexlify(hex_key)
        if len(key) != KEY_SIZE:
            print(f"Error: Key must be {KEY_SIZE} bytes ({KEY_SIZE*2} hex chars) long.")
            return None
        return key
    except binascii.Error:
        print("Error: Invalid hex string provided.")
        return None


def main():
    if len(sys.argv) != 3:
        print_usage()

    input_file = sys.argv[1]
    mode = sys.argv[2].lower()

    if mode == "enc":
        key = get_random_bytes(KEY_SIZE)
        print(f"AES-256-GCM KEY: {binascii.hexlify(key).decode('utf-8')}")
        encrypt_file(input_file, key)

    elif mode == "dec":
        key = get_key_from_user()
        if key:
            decrypt_file(input_file, key)

    else:
        print(f"Error: Unknown mode '{mode}'.")
        print_usage()


if __name__ == "__main__":
    main()
