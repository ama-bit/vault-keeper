# Vault Keeper ☢️
## Beginner-Friendly Encrypted Password Vault (Python)

  - Vault Keeper is a beginner-friendly Python learning project for building a basic encrypted password vault from scratch.

  - The focus is on understanding how encrypted password storage works, not on creating a production-ready password manager.

---

## Project Goals 🥅

  1. Learn how passwords can be encrypted at rest
    
  2. Understand encryption vs hashing
    
  3. Practice deriving keys from a master password
    
  4. Safely store and retrieve secrets from disk
    
  5. Think clearly about security assumptions and limits

---

## What Vault Keeper Does

  - Derives an encryption key from a master password

  - Encrypts password entries before saving them

  - Stores secrets in a local encrypted vault file

  - Decrypts data only after successful authentication

  - Demonstrates common secure-storage patterns

---

## What Vault Keeper is Not

❌ A production password manager

❌ A replacement for audited security tools

❌ Safe for real credentials

---

## How It Works 🔎

At a high level:

  1. User sets a master password
     
  2. A cryptographic key is derived from that password
     
  3. Password entries are encrypted
     
  4. Encrypted data is written to disk
     
  5. Data is decrypted only with the correct master password

---

## Threat Model (Educational)

Vault Keeper assumes a local attacker who may gain access to the vault file but does *not* know the master password.

**Defends against:**

  - Plaintext password storage

  - Accidental exposure of secrets

  - Basic offline inspection

**Does not defend against:**

  - Malware or keyloggers

  - Weak master passwords

  - OS compromise

  - Advanced cryptographic attacks

>
>⚠️ This threat model is intentionally limited for learning.
>

---

## Tools 🧰

- Python standard library

- hashlib

- secrets

- os

- json

(Crypto choices will be documented as the project evolves.)

---

## How to Run ⏯️

1. Clone the repository

2. Ensure Python 3.9+ is installed

3. Run:

`python vault-keeper.py`

---

## Example of Output

```bash
Welcome to VaultKeeper 🔐

Create a master password:
✔ Vault initialized.

Add entry:
Service: github
Username: v4u1t-k33p3r
Password: ********
✔ Entry encrypted and stored.

Unlock vault:
Enter master password:
✔ Vault unlocked.
```

---

## Security Notes 🔏

  - Master password strength matters

  - Encrypted ≠ invulnerable

  - Never hard-code secrets

  - Prefer audited tools for real-world use

---

## License

- MIT License - see `LICENSE` for details.

---
