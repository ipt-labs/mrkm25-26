# app.py

import os
import hashlib
import time
import json
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractLogicError
from dotenv import load_dotenv

# --- Configuration ---
load_dotenv()
GANACHE_URL = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS") # Reads from .env
ABI_PATH = Path("build") / "contracts" / "ContentRegistry.json"

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Web3 and Contract Setup ---
try:
    if not CONTRACT_ADDRESS:
        raise ValueError("CONTRACT_ADDRESS not found in .env file. Please run the deploy script.")
    w3 = Web3(HTTPProvider(GANACHE_URL))
    if not w3.is_connected():
        raise ConnectionError(f"Failed to connect to Ganache at {GANACHE_URL}")
    print(f"Connected to Ganache: {GANACHE_URL}")
except Exception as e:
    print(f"CRITICAL: Ganache connection error: {e}")
    exit()

try:
    with open(ABI_PATH, 'r') as f:
        contract_json = json.load(f)
        contract_abi = contract_json['abi']
except Exception as e:
     print(f"CRITICAL: Failed to load ABI from {ABI_PATH}. Run 'brownie compile'. Error: {e}")
     exit()

try:
    checksum_address = w3.to_checksum_address(CONTRACT_ADDRESS)
    contract = w3.eth.contract(address=checksum_address, abi=contract_abi)
    print(f"Contract instance loaded: {contract.address}")
except Exception as e:
     print(f"CRITICAL: Failed to create contract instance for {CONTRACT_ADDRESS}. Error: {e}")
     exit()

def calculate_file_hash(file_stream):
    hash_obj = hashlib.sha256()
    for chunk in iter(lambda: file_stream.read(4096), b""):
        hash_obj.update(chunk)
    file_stream.seek(0)
    return hash_obj.digest()

def get_ganache_accounts():
    try:
        return w3.eth.accounts
    except Exception as e:
        print(f"Error getting Ganache accounts: {e}")
        return []

# --- Flask Routes ---
@app.route('/')
def index():
    # The accounts list is no longer used for registration, but we can keep it for now.
    ganache_accounts = get_ganache_accounts()
    return render_template('index.html', accounts=ganache_accounts, verification_result=None)

# --- /register route ---
@app.route('/register', methods=['POST'])
def register():
    # Expect JSON data from the client-side fetch request
    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid JSON payload'}), 400

    content_hash_hex = data.get('contentHash')
    signature_hex = data.get('signature')
    selected_account = data.get('account')

    if not all([content_hash_hex, signature_hex, selected_account]):
        flash('Incomplete data received from client.', 'error')
        return jsonify({'status': 'error', 'message': 'Missing hash, signature, or account.'}), 400

    try:
        # Convert hex strings from client to bytes for the smart contract
        content_hash_bytes = bytes.fromhex(content_hash_hex[2:])
        signature_bytes = bytes.fromhex(signature_hex[2:])

        print(f"Sending registerContent transaction from {selected_account}...")
        print(f"Hash: {content_hash_hex}")
        print(f"Signature: {signature_hex}")

        # Call the new smart contract function with the signature
        tx_hash = contract.functions.registerContent(
            content_hash_bytes,
            signature_bytes
        ).transact({
            'from': selected_account,
            'gas': 500000  # Gas might be slightly higher due to signature verification
        })

        print(f"Waiting for transaction receipt: {tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        if receipt.status == 1:
            flash(f'Content signed and registered successfully! Tx: {receipt.transactionHash.hex()}', 'success')
            print(f"Transaction successful: {receipt.transactionHash.hex()}")
            return jsonify({'status': 'success', 'txHash': receipt.transactionHash.hex()})
        else:
            flash('Registration failed: Transaction reverted.', 'error')
            print(f"Transaction failed (status=0): {receipt.transactionHash.hex()}")
            return jsonify({'status': 'error', 'message': 'Transaction reverted'}), 500

    except ContractLogicError as e:
        # This will catch errors from the `require` statements in the contract
        # e.g., "Invalid signature" or "Content hash already registered"
        error_message = str(e)
        flash(f'Contract Error: {error_message}', 'error')
        print(f"Contract logic error: {error_message}")
        return jsonify({'status': 'error', 'message': f'Contract Logic Error: {error_message}'}), 400
    except Exception as e:
        flash(f'An unexpected server error occurred: {e}', 'error')
        print(f"General registration error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# --- /verify route ---
@app.route('/verify', methods=['POST'])
def verify():
    ganache_accounts = get_ganache_accounts()
    content_hash_bytes = None
    content_hash_hex = None
    file = request.files.get('verifyFile')
    hash_input = request.form.get('verifyHash')
    verification_result = {}

    if file and file.filename != '':
        try:
            content_hash_bytes = calculate_file_hash(file.stream)
            content_hash_hex = "0x" + content_hash_bytes.hex()
            print(f"Calculated hash for verification (from file): {content_hash_hex}")
        except Exception as e:
            flash(f'Error processing file: {e}', 'error')
            return render_template('index.html', accounts=ganache_accounts, verification_result=None)
    elif hash_input:
         if not (hash_input.startswith('0x') and len(hash_input) == 66):
             flash('Invalid hash format (must be 0x followed by 64 hex chars).', 'error')
             return render_template('index.html', accounts=ganache_accounts, verification_result=None)
         try:
            content_hash_bytes = bytes.fromhex(hash_input[2:])
            content_hash_hex = hash_input
            print(f"Hash for verification (input): {content_hash_hex}")
         except ValueError:
              flash('Invalid hash format (cannot convert to bytes).', 'error')
              return render_template('index.html', accounts=ganache_accounts, verification_result=None)
    else:
         flash('No file selected or hash entered for verification.', 'error')
         return render_template('index.html', accounts=ganache_accounts, verification_result=None)

    if content_hash_bytes and content_hash_hex:
        try:
            is_registered = contract.functions.isRegistered(content_hash_bytes).call()

            if is_registered:
                owner, timestamp, signature_bytes = contract.functions.verifyOwnership(content_hash_bytes).call()
                verification_result = {
                    'hash': content_hash_hex,
                    'owner': owner,
                    'timestamp': timestamp,
                    'time_str': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(timestamp)),
                    # Add the signature to the results, converting bytes to a hex string for display
                    'signature': "0x" + signature_bytes.hex(),
                    'error': None
                }
                print(f"Verification result: Owner={owner}, Timestamp={timestamp}")
            else:
                 verification_result = {
                     'hash': content_hash_hex,
                     'error': f"Content with hash {content_hash_hex[:10]}... not found in registry."
                 }
                 print(f"Verification result: Hash {content_hash_hex} not found.")

        except ContractLogicError as e:
             print(f"Contract logic error during verification: {e}")
             verification_result = {
                 'hash': content_hash_hex,
                 'error': f"Contract error verifying hash {content_hash_hex[:10]}... ({e})"
             }
        except Exception as e:
            flash(f'Server error during verification: {e}', 'error')
            print(f"Error calling contract function: {e}")
            verification_result = {'error': f"Blockchain interaction error: {e}"}

    return render_template('index.html', accounts=ganache_accounts, verification_result=verification_result)

# --- Server Start ---
if __name__ == '__main__':
    print(f"Starting Flask server on http://127.0.0.1:5000")
    # Redundant prints already handled in setup blocks
    # print(f"Connected to Ganache: {GANACHE_URL}")
    # print(f"Using contract: {CONTRACT_ADDRESS}")
    app.run(host='0.0.0.0', port=5000, debug=True)