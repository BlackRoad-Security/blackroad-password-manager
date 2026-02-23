# blackroad-password-manager

> CLI password manager with encryption — BlackRoad Security

[![CI](https://github.com/BlackRoad-Security/blackroad-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/BlackRoad-Security/blackroad-password-manager/actions/workflows/ci.yml)

Secure CLI password vault with master-password protection. **No external dependencies** — uses `hashlib.pbkdf2_hmac` + XOR cipher with per-field random salts. SQLite backend.

## Features

- 🔐 **PBKDF2-HMAC-SHA256**: 600,000 iterations key derivation
- 🎲 **Per-field encryption**: Each field encrypted with unique 32-byte salt
- 🔑 **Password generator**: Cryptographically secure (`secrets` module)
- 📊 **Strength scoring**: 0–100 password quality scoring
- 🔍 **Audit tools**: Find weak and reused passwords
- 📤 **CSV export**: Export decrypted vault (requires master password)
- 🔍 **Search**: Find entries by site, username, URL, or tags
- 💾 **SQLite**: Single-file vault, zero-config

## Quick Start

```bash
# Initialize vault
python password_manager.py init "YourMasterP@ss!"

# Add entry
python password_manager.py add "YourMasterP@ss!" github.com user@email.com "MyGhP@ss!"

# Get entry (shows decrypted password)
python password_manager.py get "YourMasterP@ss!" github

# Generate a strong password
python password_manager.py generate 24

# Search entries
python password_manager.py search "YourMasterP@ss!" github

# Audit weak passwords
python password_manager.py audit-weak "YourMasterP@ss!"

# Audit reused passwords
python password_manager.py audit-reused "YourMasterP@ss!"

# View stats
python password_manager.py stats "YourMasterP@ss!"

# Export to CSV
python password_manager.py export "YourMasterP@ss!" vault_backup.csv

# Run demo
python password_manager.py demo
```

## Encryption Design

```
Master Password ──PBKDF2──► Derived Key (32 bytes, 600k iterations)
                               │
                               ▼
                           XOR Cipher
                         + Random Salt (32 bytes per field)
                               │
                               ▼
                        Stored as hex(salt + ciphertext)
```

Each encrypted field has its own unique random salt. The master key is never stored — only a PBKDF2 hash for verification.

## API

```python
from password_manager import PasswordManager

pm = PasswordManager("vault.db")
pm.init_vault("MyMasterP@ss!")

# Add entries
entry = pm.add_entry("github.com", "user@email.com", "MyP@ss!", url="https://github.com")

# Retrieve
plain_pw = pm.get_entry_password("github.com")

# Generate password
pw = pm.generate_password(length=24, symbols=True)

# Audit
weak = pm.audit_weak(threshold=50)
reused = pm.audit_reused()

# Export
count = pm.export_csv("MyMasterP@ss!", "backup.csv")
```

## Running Tests

```bash
pip install pytest
pytest test_password_manager.py -v
```
