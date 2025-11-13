# scripts/deploy_web3.py

import json
import os
from web3 import Web3
from dotenv import load_dotenv, find_dotenv
from pathlib import Path


def update_env_file(key_to_update, new_value):
    env_file = find_dotenv()
    if not env_file:
        env_file = ".env" # Create .env in the current directory if not found

    # Read existing values
    env_vars = {}
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    env_vars[key] = value

    # Update the specific key
    env_vars[key_to_update] = new_value

    # Write all values back to the file
    with open(env_file, 'w') as f:
        for key, value in env_vars.items():
            f.write(f"{key}={value}\n")
    print(f"✅ Файл .env оновлено: {key_to_update} = {new_value}")


load_dotenv()
GANACHE_URL = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
BUILD_DIR = Path("build")
ABI_FILE = BUILD_DIR / "contracts" / "ContentRegistry.json"
DEPLOYER_ACCOUNT_INDEX = 0

def main():
    print(f"Підключення до Ganache: {GANACHE_URL}")
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    if not w3.is_connected():
        print("ПОМИЛКА: Не вдалося підключитися до Ganache.")
        return

    try:
        with open(ABI_FILE, 'r') as f:
            contract_json = json.load(f)
            abi = contract_json['abi']
            bytecode = contract_json['bytecode']
    except FileNotFoundError:
         print(f"ПОМИЛКА: Не знайдено файл {ABI_FILE}. Запустіть 'brownie compile'.")
         return
    except KeyError:
         print(f"ПОМИЛКА: Не вдалося знайти 'abi' або 'bytecode' у файлі {ABI_FILE}.")
         return
    except Exception as e:
        print(f"ПОМИЛКА завантаження ABI/байткоду: {e}")
        return

    try:
        deployer_account = w3.eth.accounts[DEPLOYER_ACCOUNT_INDEX]
        print(f"Акаунт розгортання: {deployer_account}")
        print(f"Баланс: {w3.from_wei(w3.eth.get_balance(deployer_account), 'ether')} ETH")
    except IndexError:
        print(f"ПОМИЛКА: Акаунт з індексом {DEPLOYER_ACCOUNT_INDEX} не знайдено в Ganache.")
        return
    except Exception as e:
         print(f"ПОМИЛКА отримання акаунту: {e}")
         return

    print("Розгортання контракту ContentRegistry...")
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    try:
        tx_hash = Contract.constructor().transact({'from': deployer_account, 'gas': 1500000})
        print(f"Транзакцію надіслано: {tx_hash.hex()}")
        print("Очікування підтвердження...")
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        if tx_receipt.status == 1:
            contract_address = tx_receipt.contractAddress
            print("-" * 50)
            print(f"КОНТРАКТ УСПІШНО РОЗГОРНУТО в Ganache UI!")
            print(f"Адреса: {contract_address}")
            print(f"Блок: {tx_receipt.blockNumber}")
            print("-" * 50)
            # --- Start of Modifications ---
            update_env_file("CONTRACT_ADDRESS", contract_address)
            # --- End of Modifications ---
        else:
            print("ПОМИЛКА: Розгортання не вдалося (транзакція revert).")

    except Exception as e:
        print(f"ПОМИЛКА під час розгортання: {e}")

if __name__ == "__main__":
    main()