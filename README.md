# Vault Keeper ☢️  
## Python Password Vault (Educational Demo)

- Vault Keeper is a beginner-friendly Python learning project demonstrating how a simple **in-memory password manager** works.  

- The goal is to understand **password encryption, key derivation, and secure handling** in a safe, interactive session.  

- This is **not** a production-ready password manager.

---

## Goals

1. Learn how passwords can be encrypted at rest (in memory).
     
3. Understand *encryption vs hashing*.  

4. Practice deriving keys from a master password **(PBKDF2-HMAC-SHA256)**.  

5. Safely manage secrets in a session-only vault.  

6. Think critically about security assumptions and limitations.  

---

## What Vault Keeper Does ❓

- Derives an encryption key from a master password.  

- Encrypts password entries before storing them in memory.  

- Decrypts data only after successful authentication.  

- Demonstrates secure-storage patterns and workflow.  

- Provides an interactive CLI for adding and viewing entries.  

---

## Vault Keeper is NOT:

❌ A production password manager.  

❌ A replacement for audited security tools.  

❌ Safe for real credentials.  

---

## How It Works 🔎

At a high level:

1. User creates a master password.
     
3. A cryptographic key is derived from the master password using PBKDF2.
    
5. Password entries are encrypted in memory with XOR (for demo purposes).
   
7. Entries remain in memory only; nothing is saved to disk.
   
9. Data is decrypted only with the master password.  

---

## Educational Threat Model  

Vault Keeper assumes a **local, educational environment**.  

### **Defends against:**

- Storing plaintext passwords in memory carelessly.
  
*Demonstrating encryption/decryption workflow*. 


### **Does not defend against:**  

- Malware or keyloggers.
  
- Weak master passwords.
  
- OS compromise or advanced cryptographic attacks.  


> ⚠️ This threat model is intentionally limited for learning purposes.  

---

## Tools 🧰

- Python standard library  

- `hashlib` (PBKDF2 key derivation)  

- `secrets` (random salt generation)  

- `getpass` (hidden password input)  

- `json` (dict serialization for encryption/decryption)  

*(All operations occur in memory, no files are written.)*  

---

## How to Run ⏯️

1. Ensure Python 3.9+ is installed

2. Clone the repository  

3. Navigate to directory: `cd vault-keeper`

4. Run:

```bash
python vault-keeper.py
```

---

## Example of Output

```bash
====================================
    Welcome to Vault Keeper!
====================================

Create master password:
✔ Vault initialized.

Add entry:
Service: github
Username: v4u1t-k33p3r
Password: ********
✔ Entry added to vault (in-memory).

View vault:
{
  "github": {
    "username": "v4u1t-k33p3r",
    "password": "badpassword321"
  }
}

Exit program:
Thank you & Goodbye!
```

---

## Security Notes 🔏

  - Master password strength is important.
    
  - XOR encryption is for **demonstration only** and **not** secure for real passwords.
    
  - Vault exists only in memory; restarting the script clears all data.
    
---

## License

- MIT License - see `LICENSE` for details.

---
