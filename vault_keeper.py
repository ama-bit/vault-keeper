"""
Vault Keeper
Python Password Manager – Educational Use Only
"""

# =========================
# Imports
# =========================
import os          # File operations
import json        # Read/write JSON vault
import hashlib     # Key derivation
import secrets     # Random salt generation
import getpass     # Hidden password input

# =========================
# Constants
# =========================
VAULT_FILE = "vault.json"  # Vault filename
SALT_SIZE = 16             # Number of bytes for salt
ITERATIONS = 100_000       # PBKDF2 iterations for key derivation
APP_STATE = "LOCKED"       # Current session state

# =========================
# UI Helpers
# =========================
def banner():
    """Prints the program banner."""
    print("""
====================================
    Welcome to Vault Keeper!
====================================

A Python Password Manager for Educational Use Only!
""")

def status_bar(state: str, width: int = 50):
    """Displays a CLI-style status bar for the current app state."""
    print(f"\n{' STATUS: ' + state + ' ':-^{width}}")

def menu() -> str:
    """Displays menu options and returns the user's choice."""
    print("""
----------- MENU ------------------

1) Add Entry
2) View Entries
3) Exit

-----------------------------------
""")
    return input("Select option > ").strip()

# =========================
# Crypto Helpers
# =========================
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a secure 32-byte key from the master password and salt."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, dklen=32)

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt or decrypt data using XOR (symmetric)."""
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt using XOR (same as encryption)."""
    return xor_encrypt(ciphertext, key)

# =========================
# Vault Helpers
# =========================
def initialize_vault(master_password: str) -> tuple[dict, bytes]:
    """
    Creates a new empty vault with a fresh random salt.
    Returns the vault dictionary and salt for the session.
    """
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(master_password, salt)
    vault = {}  # Empty vault dictionary
    encrypted = xor_encrypt(json.dumps(vault).encode(), key)

    # Save encrypted vault to disk
    with open(VAULT_FILE, "w") as f:
        json.dump({"salt": salt.hex(), "data": encrypted.hex()}, f, indent=2)

    status_bar("NEW VAULT")
    print("Vault initialized.")
    return vault, salt

def unlock_vault(master_password: str, salt: bytes) -> dict:
    """
    Unlocks the vault using the master password and salt.
    Returns the decrypted vault dictionary.
    """
    with open(VAULT_FILE, "r") as f:
        vault_data = json.load(f)

    encrypted_data = bytes.fromhex(vault_data["data"])
    key = derive_key(master_password, salt)
    decrypted = xor_decrypt(encrypted_data, key)

    return json.loads(decrypted.decode())

def save_vault(vault: dict, master_password: str, salt: bytes):
    """Encrypts and saves the vault dictionary to disk."""
    key = derive_key(master_password, salt)
    encrypted = xor_encrypt(json.dumps(vault).encode(), key)

    with open(VAULT_FILE, "w") as f:
        json.dump({"salt": salt.hex(), "data": encrypted.hex()}, f, indent=2)

    status_bar("SAVED")
    print("Vault saved.")

def add_entry(vault: dict) -> dict:
    """Prompts the user to add a new service entry."""
    service = input("Service name: ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    vault[service] = {"username": username, "password": password}
    print(f"Entry added for '{service}'.")
    return vault

# =========================
# Main Program
# =========================
def main():
    global APP_STATE
    APP_STATE = "LOCKED"  # Reset session state

    banner()

    # -------------------------------
    # Fresh session: delete old vault silently
    # -------------------------------
    if os.path.exists(VAULT_FILE):
        os.remove(VAULT_FILE)

    # -------------------------------
    # Create new vault and unlock for this session
    # -------------------------------
    master_password = getpass.getpass("Create master password: ")
    vault, salt = initialize_vault(master_password)
    vault = unlock_vault(master_password, salt)
    APP_STATE = "UNLOCKED"
    status_bar(APP_STATE)

    # -------------------------------
    # Main menu loop
    # -------------------------------
    while True:
        choice = menu()
        if choice == "1":  # Add Entry
            vault = add_entry(vault)
            save_vault(vault, master_password, salt)
        elif choice == "2":  # View Entries
            print(json.dumps(vault, indent=2))
        elif choice == "3":  # Exit
            status_bar("EXITING")
            print("Goodbye.")
            break
        else:
            print("Invalid option.")

# =========================
# Entry Point
# =========================
if __name__ == "__main__":
    main()
