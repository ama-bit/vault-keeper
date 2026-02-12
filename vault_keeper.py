"""
Vault Keeper
Python Password Manager – Educational Use Only
"""

# =========================
# Imports
# =========================
import json        # Convert Python dicts to/from strings for encryption
import hashlib     # Key derivation (PBKDF2)
import secrets     # Generate secure random salts
import getpass     # Hidden password input for master password & entries

# =========================
# Constants
# =========================
SALT_SIZE = 16          # Number of bytes in the random salt
ITERATIONS = 100_000    # PBKDF2 iterations for key derivation
APP_STATE = "LOCKED"    # Current session state (LOCKED / UNLOCKED)

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
    """
    Prints a CLI-style status bar for the current app state.
    Example: [ STATUS: UNLOCKED                      ]
    """
    print(f"\n{' STATUS: ' + state + ' ':-^{width}}")

def menu() -> str:
    """
    Displays the main menu options and returns the user's choice.
    Strips extra whitespace for cleaner input handling.
    """
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
    """
    Derives a 32-byte cryptographic key from the master password and salt.
    Uses PBKDF2-HMAC-SHA256 to slow down brute-force attacks.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",              # Hash function
        password.encode(),     # Convert password to bytes
        salt,                  # Random salt
        ITERATIONS,            # Number of iterations
        dklen=32               # Output key length (32 bytes = 256 bits)
    )

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """
    Encrypts or decrypts data using XOR with the provided key.
    Symmetric: same function is used for both encryption and decryption.
    Repeats key bytes if data is longer than the key.
    """
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypts data using XOR (same as encryption)."""
    return xor_encrypt(ciphertext, key)

# =========================
# Vault Helpers (In-Memory)
# =========================
def initialize_vault(master_password: str) -> tuple[dict, bytes, bytes]:
    """
    Creates a new empty vault with a fresh random salt.
    Returns:
        vault (dict): Empty dictionary for session entries
        salt (bytes): Random salt for key derivation
        encrypted (bytes): Initial encrypted vault for in-memory use
    """
    # Generate a new random salt
    salt = secrets.token_bytes(SALT_SIZE)
    
    # Derive encryption key from master password + salt
    key = derive_key(master_password, salt)
    
    # Initialize empty vault
    vault = {}
    
    # Encrypt the empty vault in memory
    encrypted = xor_encrypt(json.dumps(vault).encode(), key)

    # Display status for the user
    status_bar("NEW VAULT")
    print("Vault initialized.")
    
    return vault, salt, encrypted

def unlock_vault(master_password: str, salt: bytes, encrypted_data: bytes) -> dict:
    """
    Decrypts an in-memory vault using the master password and salt.
    Returns the vault as a Python dictionary.
    """
    # Derive the same key using the master password + salt
    key = derive_key(master_password, salt)
    
    # Decrypt the XOR-encrypted vault bytes
    decrypted = xor_decrypt(encrypted_data, key)
    
    # Convert bytes back into a Python dictionary using JSON
    return json.loads(decrypted.decode())

def save_vault(vault: dict, master_password: str, salt: bytes) -> bytes:
    """
    Encrypts the vault in memory.
    Returns encrypted bytes for continued session use.
    """
    # Derive key again for encryption
    key = derive_key(master_password, salt)
    
    # Encrypt the vault dictionary
    encrypted = xor_encrypt(json.dumps(vault).encode(), key)

    # Display save status
    status_bar("SAVED")
    print("Vault saved (in-memory).")
    
    return encrypted

def add_entry(vault: dict) -> dict:
    """
    Prompts the user to add a new service entry.
    Updates the vault dictionary in memory.
    """
    # Collect entry data from user
    service = input("Service name: ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    # Add new entry to the vault
    vault[service] = {"username": username, "password": password}
    print(f"Entry added for '{service}'.")
    
    return vault

# =========================
# Main Program
# =========================
def main():
    global APP_STATE
    APP_STATE = "LOCKED"

    banner()

    # Prompt user to create master password
    master_password = getpass.getpass("Create master password: ")

    # Initialize empty vault and get encrypted bytes
    vault, salt, encrypted = initialize_vault(master_password)

    # Unlock vault in memory for the session
    vault = unlock_vault(master_password, salt, encrypted)
    APP_STATE = "UNLOCKED"
    status_bar(APP_STATE)

    # Main menu loop
    while True:
        choice = menu()
        if choice == "1":  # Add Entry
            vault = add_entry(vault)
            encrypted = save_vault(vault, master_password, salt)
        elif choice == "2":  # View Entries
            print(json.dumps(vault, indent=2))
        elif choice == "3":  # Exit
            status_bar("EXITING")
            print("Thank You & Goodbye!")
            break
        else:
            print("Invalid option.")

# =========================
# Entry Point
# =========================
if __name__ == "__main__":
    main()
