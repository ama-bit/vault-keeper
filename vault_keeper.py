"""
Welcome to Vault Keeper!

This is a Beginner-Friendly, Encrypted Password Manager (vault)
made in Python as a Learning Project.

Educational use only — not production secure.
"""

# =========================
# Imports
# =========================

import os
import json
import hashlib
import secrets


# =========================
# Constants & Config
# =========================

VAULT_FILE = "vault.json"
SALT_SIZE = 16
ITERATIONS = 100_000


# =========================
# Helper Functions
# =========================

def derive_key(master_password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=master_password.encode(),
        salt=salt,
        iterations=ITERATIONS,
        dklen=32
    )


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    encrypted = bytearray()
    for i in range(len(data)):
        encrypted.append(data[i] ^ key[i % len(key)])
    return bytes(encrypted)


def xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return xor_encrypt(ciphertext, key)


# =========================
# Vault Operations
# =========================

def initialize_vault(master_password: str):
    if os.path.exists(VAULT_FILE):
        print("Vault already exists.")
        return

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(master_password, salt)

    empty_vault = json.dumps({}).encode()
    encrypted_vault = xor_encrypt(empty_vault, key)

    vault_data = {
        "salt": salt.hex(),
        "data": encrypted_vault.hex()
    }

    with open(VAULT_FILE, "w") as f:
        json.dump(vault_data, f)

    print("✔ Vault initialized.")


def unlock_vault(master_password: str):
    if not os.path.exists(VAULT_FILE):
        print("Vault not found.")
        return None, None

    with open(VAULT_FILE, "r") as f:
        vault_data = json.load(f)

    salt = bytes.fromhex(vault_data["salt"])
    encrypted_data = bytes.fromhex(vault_data["data"])

    key = derive_key(master_password, salt)

    try:
        decrypted = xor_decrypt(encrypted_data, key)
        vault = json.loads(decrypted.decode())
        return vault, salt
    except Exception:
        print("Incorrect master password.")
        return None, None


def save_vault(vault: dict, master_password: str, salt: bytes):
    key = derive_key(master_password, salt)
    plaintext = json.dumps(vault).encode()
    encrypted = xor_encrypt(plaintext, key)

    vault_data = {
        "salt": salt.hex(),
        "data": encrypted.hex()
    }

    with open(VAULT_FILE, "w") as f:
        json.dump(vault_data, f)

    print("✔ Vault saved.")


def add_entry(vault: dict) -> dict:
    service = input("Service name: ")
    username = input("Username: ")
    password = input("Password: ")

    vault[service] = {
        "username": username,
        "password": password
    }

    print(f"✔ Entry added for '{service}'.")
    return vault


# =========================
# Main Program Flow
# =========================

def main():
    print("Welcome to Vault Keeper!")

    if not os.path.exists(VAULT_FILE):
        master_password = input("Create a master password: ")
        initialize_vault(master_password)
        return

    master_password = input("Enter master password to unlock vault: ")
    vault, salt = unlock_vault(master_password)

    if vault is None:
        return

    print("✔ Vault unlocked.")

    print("\n1. View entries")
    print("2. Add entry")
    choice = input("> ")

    if choice == "1":
        print(json.dumps(vault, indent=2))

    elif choice == "2":
        vault = add_entry(vault)
        save_vault(vault, master_password, salt)

    else:
        print("Invalid option.")


# =========================
# Run Program
# =========================

if __name__ == "__main__":
    main()
