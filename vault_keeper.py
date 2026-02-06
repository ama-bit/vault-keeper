"""
Welcome to Vault Keeper

A Beginner-Friendly, Encrypted Password Vault made in Python as a Learning Project.

The goal is to understand *how encrypted password storage works*,
not to build a production-ready password manager.

"""

# =========================
# Imports
# =========================

import os          # File system operations (checking, reading, writing files)
import json        # Structured storage for vault data
import hashlib     # Cryptographic hashing & key derivation
import secrets     # Cryptographically secure random values


# =========================
# Constants & Config.
# =========================

VAULT_FILE = "vault.json"   # Where encrypted data will be stored on disk
SALT_SIZE = 16              # Bytes of randomness for key derivation
ITERATIONS = 100_000        # PBKDF2 work factor (slow on purpose)


# =========================
# Helper Functions
# =========================

def derive_key(master_password: str, salt: bytes) -> bytes:
    
    """
    Derives a cryptographic key from a master password.

    Why this matters:
    
    - Passwords are low entropy
    
    - Keys must be high entropy
    
    - PBKDF2 makes brute-force attacks harder

    This function turns a human password into a fixed-length key.
    """

    return hashlib.pbkdf2_hmac(
        hash_name="sha256",               # Hash algorithm
        password=master_password.encode(),# Convert string → bytes
        salt=salt,                        # Random salt
        iterations=ITERATIONS,            # Slows down attackers
        dklen=32                          # 256-bit derived key
    )


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    
    """
    VERY SIMPLE encryption using XOR.

    Educational only!
    This demonstrates the *idea* of encryption,
    not secure cryptography.

    Real systems use audited libraries like Fernet or AES-GCM.
    """

    encrypted = bytearray()

    for i in range(len(data)):
        encrypted.append(data[i] ^ key[i % len(key)])

    return bytes(encrypted)


def xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    
    """
    XOR decryption is identical to encryption.
    Applying the same operation reverses the data.
    """
    return xor_encrypt(ciphertext, key)


# =========================
# Vault Operations
# =========================

def initialize_vault(master_password: str):
    
    """
    Creates a new encrypted vault file.

    Steps:
    1. Generate a random salt
    2. Derive a key from the master password
    3. Store metadata (salt + empty vault)
    """

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


def unlock_vault(master_password: str) -> dict | None:
    
    """
    Unlocks and decrypts the vault using the master password.

    Returns:
    
    - Decrypted vault dictionary if successful
    
    - None if password is incorrect or data is invalid
    
    """

    if not os.path.exists(VAULT_FILE):
        print("Vault not found.")
        return None

    with open(VAULT_FILE, "r") as f:
        vault_data = json.load(f)

    salt = bytes.fromhex(vault_data["salt"])
    encrypted_data = bytes.fromhex(vault_data["data"])

    key = derive_key(master_password, salt)

    try:
        decrypted = xor_decrypt(encrypted_data, key)
        return json.loads(decrypted.decode())
    except Exception:
        # If decryption fails, the password is likely wrong
        print("Incorrect master password.")
        return None


# =========================
# Main Program Flow
# =========================

def main():
    """
    Entry point for the program.

    For Day One, this only supports:
    
    - Initializing a vault
    
    - Unlocking a vault


    Features like adding entries come later.
    """

    print("Welcome to Vault Keeper!")

    if not os.path.exists(VAULT_FILE):
        master_password = input("Create a master password: ")
        initialize_vault(master_password)
    else:
        master_password = input("Enter master password to unlock vault: ")
        vault = unlock_vault(master_password)

        if vault is not None:
            print("✔ Vault unlocked.")
            print("Stored entries:", vault)


# =========================
# Run Program
# =========================

if __name__ == "__main__":
    main()
