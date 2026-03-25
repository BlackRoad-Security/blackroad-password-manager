<!-- BlackRoad SEO Enhanced -->

# ulackroad password manager

> Part of **[BlackRoad OS](https://blackroad.io)** — Sovereign Computing for Everyone

[![BlackRoad OS](https://img.shields.io/badge/BlackRoad-OS-ff1d6c?style=for-the-badge)](https://blackroad.io)
[![BlackRoad Security](https://img.shields.io/badge/Org-BlackRoad-Security-2979ff?style=for-the-badge)](https://github.com/BlackRoad-Security)
[![License](https://img.shields.io/badge/License-Proprietary-f5a623?style=for-the-badge)](LICENSE)

**ulackroad password manager** is part of the **BlackRoad OS** ecosystem — a sovereign, distributed operating system built on edge computing, local AI, and mesh networking by **BlackRoad OS, Inc.**

## About BlackRoad OS

BlackRoad OS is a sovereign computing platform that runs AI locally on your own hardware. No cloud dependencies. No API keys. No surveillance. Built by [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc), a Delaware C-Corp founded in 2025.

### Key Features
- **Local AI** — Run LLMs on Raspberry Pi, Hailo-8, and commodity hardware
- **Mesh Networking** — WireGuard VPN, NATS pub/sub, peer-to-peer communication
- **Edge Computing** — 52 TOPS of AI acceleration across a Pi fleet
- **Self-Hosted Everything** — Git, DNS, storage, CI/CD, chat — all sovereign
- **Zero Cloud Dependencies** — Your data stays on your hardware

### The BlackRoad Ecosystem
| Organization | Focus |
|---|---|
| [BlackRoad OS](https://github.com/BlackRoad-OS) | Core platform and applications |
| [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc) | Corporate and enterprise |
| [BlackRoad AI](https://github.com/BlackRoad-AI) | Artificial intelligence and ML |
| [BlackRoad Hardware](https://github.com/BlackRoad-Hardware) | Edge hardware and IoT |
| [BlackRoad Security](https://github.com/BlackRoad-Security) | Cybersecurity and auditing |
| [BlackRoad Quantum](https://github.com/BlackRoad-Quantum) | Quantum computing research |
| [BlackRoad Agents](https://github.com/BlackRoad-Agents) | Autonomous AI agents |
| [BlackRoad Network](https://github.com/BlackRoad-Network) | Mesh and distributed networking |
| [BlackRoad Education](https://github.com/BlackRoad-Education) | Learning and tutoring platforms |
| [BlackRoad Labs](https://github.com/BlackRoad-Labs) | Research and experiments |
| [BlackRoad Cloud](https://github.com/BlackRoad-Cloud) | Self-hosted cloud infrastructure |
| [BlackRoad Forge](https://github.com/BlackRoad-Forge) | Developer tools and utilities |

### Links
- **Website**: [blackroad.io](https://blackroad.io)
- **Documentation**: [docs.blackroad.io](https://docs.blackroad.io)
- **Chat**: [chat.blackroad.io](https://chat.blackroad.io)
- **Search**: [search.blackroad.io](https://search.blackroad.io)

---


> CLI password manager with encryption

Part of the [BlackRoad OS](https://blackroad.io) ecosystem — [BlackRoad-Security](https://github.com/BlackRoad-Security)

---

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
