"""
BlackRoad Password Manager - CLI vault with master password, encryption, and auditing.
No external dependencies: uses hashlib PBKDF2 + XOR cipher for encryption. SQLite backend.
"""

import csv
import hashlib
import json
import os
import secrets
import sqlite3
import string
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Encryption (PBKDF2 + XOR — stdlib only)
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 32


def _derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from the master password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )


def _xor_encrypt(plaintext: str, key: bytes) -> bytes:
    """XOR-encrypt a plaintext string using the key (key is repeated/cycled)."""
    data = plaintext.encode("utf-8")
    key_bytes = (key * ((len(data) // len(key)) + 1))[: len(data)]
    return bytes(a ^ b for a, b in zip(data, key_bytes))


def _xor_decrypt(ciphertext: bytes, key: bytes) -> str:
    """XOR-decrypt bytes back to a plaintext string."""
    key_bytes = (key * ((len(ciphertext) // len(key)) + 1))[: len(ciphertext)]
    plain = bytes(a ^ b for a, b in zip(ciphertext, key_bytes))
    return plain.decode("utf-8")


def encrypt(plaintext: str, master_password: str) -> str:
    """Encrypt plaintext and return hex-encoded: salt + ciphertext."""
    salt = secrets.token_bytes(SALT_SIZE)
    key = _derive_key(master_password, salt)
    cipher = _xor_encrypt(plaintext, key)
    return (salt + cipher).hex()


def decrypt(hex_data: str, master_password: str) -> str:
    """Decrypt hex-encoded salt+ciphertext back to plaintext."""
    raw = bytes.fromhex(hex_data)
    salt, cipher = raw[:SALT_SIZE], raw[SALT_SIZE:]
    key = _derive_key(master_password, salt)
    return _xor_decrypt(cipher, key)


def hash_master(master_password: str, salt: bytes) -> str:
    """Hash the master password for verification."""
    return hashlib.pbkdf2_hmac(
        "sha256", master_password.encode(), salt, PBKDF2_ITERATIONS, 32
    ).hex()


# ---------------------------------------------------------------------------
# Password strength
# ---------------------------------------------------------------------------

def _score_password(password: str) -> int:
    """Return a strength score 0-100."""
    score = 0
    if len(password) >= 8:  score += 10
    if len(password) >= 12: score += 15
    if len(password) >= 16: score += 15
    if any(c.isupper() for c in password): score += 15
    if any(c.islower() for c in password): score += 10
    if any(c.isdigit() for c in password): score += 15
    if any(c in string.punctuation for c in password): score += 20
    return min(score, 100)


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class Entry:
    id: str
    site: str
    username: str
    password_encrypted: str   # hex-encoded
    url: str
    notes_encrypted: str      # hex-encoded
    tags: list
    created_at: str
    last_used: str
    strength_score: int

    def to_dict(self, mask_password: bool = True) -> dict:
        d = asdict(self)
        if mask_password:
            d["password_encrypted"] = "***"
        return d


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    site TEXT NOT NULL,
    username TEXT NOT NULL,
    password_encrypted TEXT NOT NULL,
    url TEXT NOT NULL,
    notes_encrypted TEXT NOT NULL,
    tags TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used TEXT NOT NULL,
    strength_score INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_entries_site ON entries(site);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_entry(row: tuple) -> Entry:
    id_, site, user, pw_enc, url, notes_enc, tags_j, created, last_used, score = row
    return Entry(
        id=id_, site=site, username=user, password_encrypted=pw_enc,
        url=url, notes_encrypted=notes_enc, tags=json.loads(tags_j),
        created_at=created, last_used=last_used, strength_score=score,
    )


# ---------------------------------------------------------------------------
# PasswordManager
# ---------------------------------------------------------------------------

class PasswordManager:
    """CLI password manager with encrypted vault."""

    def __init__(self, db_path: str = "vault.db"):
        self.db_path = db_path
        self._master_key: Optional[bytes] = None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------
    # Vault initialisation & unlock
    # ------------------------------------------------------------------

    def init_vault(self, master_password: str) -> bool:
        """
        Create a new vault protected by master_password.
        Returns True on success, raises if vault already exists.
        """
        self._init_schema()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT value FROM vault_meta WHERE key='master_hash'"
            ).fetchone()
            if existing:
                raise RuntimeError("Vault already initialised. Use unlock_vault() to open it.")
            salt = secrets.token_bytes(SALT_SIZE)
            master_hash = hash_master(master_password, salt)
            conn.execute(
                "INSERT INTO vault_meta (key, value) VALUES (?,?)",
                ("master_hash", master_hash),
            )
            conn.execute(
                "INSERT INTO vault_meta (key, value) VALUES (?,?)",
                ("master_salt", salt.hex()),
            )
            conn.execute(
                "INSERT INTO vault_meta (key, value) VALUES (?,?)",
                ("created_at", _now()),
            )
        # Unlock immediately
        self._master_key = _derive_key(master_password, salt)
        return True

    def unlock_vault(self, master_password: str) -> bool:
        """Unlock an existing vault. Returns True on success."""
        self._init_schema()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM vault_meta WHERE key='master_salt'"
            ).fetchone()
            if not row:
                raise RuntimeError("Vault not initialised. Run init_vault() first.")
            salt = bytes.fromhex(row[0])
            stored_hash_row = conn.execute(
                "SELECT value FROM vault_meta WHERE key='master_hash'"
            ).fetchone()
            stored_hash = stored_hash_row[0]
        candidate_hash = hash_master(master_password, salt)
        if candidate_hash != stored_hash:
            self._master_key = None
            return False
        self._master_key = _derive_key(master_password, salt)
        return True

    def _require_unlocked(self):
        if self._master_key is None:
            raise RuntimeError("Vault is locked. Call unlock_vault() first.")

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """Re-encrypt all entries under a new master password."""
        if not self.unlock_vault(old_password):
            return False
        entries = self._list_all_entries()
        new_salt = secrets.token_bytes(SALT_SIZE)
        new_key = _derive_key(new_password, new_salt)
        new_hash = hash_master(new_password, new_salt)

        with self._connect() as conn:
            for entry in entries:
                plain_pw = self._decrypt_field(entry.password_encrypted)
                plain_notes = self._decrypt_field(entry.notes_encrypted)
                new_pw_enc = self._encrypt_with_key(plain_pw, new_key)
                new_notes_enc = self._encrypt_with_key(plain_notes, new_key)
                conn.execute(
                    "UPDATE entries SET password_encrypted=?, notes_encrypted=? WHERE id=?",
                    (new_pw_enc, new_notes_enc, entry.id),
                )
            conn.execute(
                "UPDATE vault_meta SET value=? WHERE key='master_hash'", (new_hash,)
            )
            conn.execute(
                "UPDATE vault_meta SET value=? WHERE key='master_salt'", (new_salt.hex(),)
            )
        self._master_key = new_key
        return True

    # ------------------------------------------------------------------
    # Encryption helpers using stored key
    # ------------------------------------------------------------------

    def _encrypt_field(self, plaintext: str) -> str:
        self._require_unlocked()
        salt = secrets.token_bytes(SALT_SIZE)
        cipher = _xor_encrypt(plaintext, self._master_key)
        return (salt + cipher).hex()

    def _decrypt_field(self, hex_data: str) -> str:
        self._require_unlocked()
        raw = bytes.fromhex(hex_data)
        # salt stored but key is already derived from master
        cipher = raw[SALT_SIZE:]
        return _xor_decrypt(cipher, self._master_key)

    def _encrypt_with_key(self, plaintext: str, key: bytes) -> str:
        salt = secrets.token_bytes(SALT_SIZE)
        cipher = _xor_encrypt(plaintext, key)
        return (salt + cipher).hex()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_entry(
        self,
        site: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        tags: list = None,
    ) -> Entry:
        """Add a new password entry."""
        self._require_unlocked()
        entry = Entry(
            id=str(uuid.uuid4()),
            site=site,
            username=username,
            password_encrypted=self._encrypt_field(password),
            url=url,
            notes_encrypted=self._encrypt_field(notes),
            tags=tags or [],
            created_at=_now(),
            last_used=_now(),
            strength_score=_score_password(password),
        )
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO entries
                   (id, site, username, password_encrypted, url, notes_encrypted,
                    tags, created_at, last_used, strength_score)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (entry.id, entry.site, entry.username, entry.password_encrypted,
                 entry.url, entry.notes_encrypted, json.dumps(entry.tags),
                 entry.created_at, entry.last_used, entry.strength_score),
            )
        return entry

    def get_entry(self, site: str) -> Optional[Entry]:
        """Fetch an entry by site name (partial match)."""
        self._require_unlocked()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM entries WHERE site LIKE ? ORDER BY last_used DESC LIMIT 1",
                (f"%{site}%",),
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE entries SET last_used=? WHERE id=?", (_now(), row[0])
                )
        return _row_to_entry(row) if row else None

    def get_entry_password(self, site: str) -> Optional[str]:
        """Get the decrypted password for a site."""
        entry = self.get_entry(site)
        if entry is None:
            return None
        return self._decrypt_field(entry.password_encrypted)

    def get_entry_by_id(self, entry_id: str) -> Optional[Entry]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
        return _row_to_entry(row) if row else None

    def update_entry(self, entry_id: str, **kwargs) -> Optional[Entry]:
        """Update fields of an existing entry."""
        self._require_unlocked()
        entry = self.get_entry_by_id(entry_id)
        if not entry:
            return None
        updates = {}
        if "site" in kwargs:
            updates["site"] = kwargs["site"]
        if "username" in kwargs:
            updates["username"] = kwargs["username"]
        if "password" in kwargs:
            updates["password_encrypted"] = self._encrypt_field(kwargs["password"])
            updates["strength_score"] = _score_password(kwargs["password"])
        if "url" in kwargs:
            updates["url"] = kwargs["url"]
        if "notes" in kwargs:
            updates["notes_encrypted"] = self._encrypt_field(kwargs["notes"])
        if "tags" in kwargs:
            updates["tags"] = json.dumps(kwargs["tags"])
        if not updates:
            return entry
        set_clause = ", ".join(f"{k}=?" for k in updates)
        with self._connect() as conn:
            conn.execute(
                f"UPDATE entries SET {set_clause}, last_used=? WHERE id=?",
                (*updates.values(), _now(), entry_id),
            )
        return self.get_entry_by_id(entry_id)

    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry by ID."""
        self._require_unlocked()
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        return cur.rowcount > 0

    def search(self, query: str) -> list:
        """Search entries by site, username, url, or tags."""
        self._require_unlocked()
        q = f"%{query}%"
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT * FROM entries
                   WHERE site LIKE ? OR username LIKE ? OR url LIKE ? OR tags LIKE ?
                   ORDER BY site""",
                (q, q, q, q),
            ).fetchall()
        return [_row_to_entry(r) for r in rows]

    def _list_all_entries(self) -> list:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM entries ORDER BY site").fetchall()
        return [_row_to_entry(r) for r in rows]

    # ------------------------------------------------------------------
    # Password generation
    # ------------------------------------------------------------------

    def generate_password(
        self,
        length: int = 20,
        uppercase: bool = True,
        digits: bool = True,
        symbols: bool = True,
        exclude_ambiguous: bool = True,
    ) -> str:
        """Generate a cryptographically secure password."""
        chars = string.ascii_lowercase
        required = [secrets.choice(string.ascii_lowercase)]
        if uppercase:
            pool = string.ascii_uppercase
            if exclude_ambiguous:
                pool = pool.translate(str.maketrans("", "", "IO"))
            chars += pool
            required.append(secrets.choice(pool))
        if digits:
            pool = string.digits
            if exclude_ambiguous:
                pool = pool.translate(str.maketrans("", "", "01"))
            chars += pool
            required.append(secrets.choice(pool))
        if symbols:
            pool = "!@#$%^&*()-_=+[]{}|;:,.<>?"
            chars += pool
            required.append(secrets.choice(pool))
        if exclude_ambiguous:
            chars = chars.translate(str.maketrans("", "", "Il1O0"))

        # Fill remaining length
        remaining = length - len(required)
        password_chars = required + [secrets.choice(chars) for _ in range(remaining)]
        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)

    # ------------------------------------------------------------------
    # Auditing
    # ------------------------------------------------------------------

    def audit_weak(self, threshold: int = 50) -> list:
        """Return entries with weak passwords (score < threshold)."""
        self._require_unlocked()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM entries WHERE strength_score < ? ORDER BY strength_score",
                (threshold,),
            ).fetchall()
        return [_row_to_entry(r) for r in rows]

    def audit_reused(self) -> list:
        """Return groups of entries sharing the same password hash."""
        self._require_unlocked()
        entries = self._list_all_entries()
        # Group by decrypted password hash (SHA-256 of plain password)
        pw_map: dict[str, list] = {}
        for entry in entries:
            try:
                plain_pw = self._decrypt_field(entry.password_encrypted)
                pw_hash = hashlib.sha256(plain_pw.encode()).hexdigest()
                pw_map.setdefault(pw_hash, []).append(entry)
            except Exception:
                continue
        return [group for group in pw_map.values() if len(group) > 1]

    def audit_old(self, days: int = 90) -> list:
        """Return entries not updated in more than `days` days."""
        self._require_unlocked()
        cutoff_ts = datetime.now(timezone.utc).timestamp() - days * 86400
        entries = self._list_all_entries()
        old = []
        for e in entries:
            try:
                ts = datetime.fromisoformat(e.last_used).timestamp()
                if ts < cutoff_ts:
                    old.append(e)
            except Exception:
                continue
        return old

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_csv(self, master_password: str, path: str) -> int:
        """Export all entries to CSV with decrypted passwords. Returns entry count."""
        if not self.unlock_vault(master_password):
            raise PermissionError("Wrong master password")
        entries = self._list_all_entries()
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["site", "username", "password", "url", "notes", "tags",
                              "created_at", "last_used", "strength_score"])
            for e in entries:
                plain_pw = self._decrypt_field(e.password_encrypted)
                plain_notes = self._decrypt_field(e.notes_encrypted)
                writer.writerow([
                    e.site, e.username, plain_pw, e.url, plain_notes,
                    ",".join(e.tags), e.created_at, e.last_used, e.strength_score,
                ])
        return len(entries)

    def vault_stats(self) -> dict:
        """Return vault statistics."""
        self._require_unlocked()
        entries = self._list_all_entries()
        scores = [e.strength_score for e in entries]
        return {
            "total_entries": len(entries),
            "weak_passwords": len([s for s in scores if s < 50]),
            "strong_passwords": len([s for s in scores if s >= 80]),
            "average_strength": sum(scores) / len(scores) if scores else 0,
            "reused_groups": len(self.audit_reused()),
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import sys
    db = PasswordManager()
    args = sys.argv[1:]

    if not args:
        print("BlackRoad Password Manager")
        print("Usage: python password_manager.py <command> [args]")
        print()
        print("Commands:")
        print("  init <master_password>              - Initialize vault")
        print("  add <master> <site> <user> <pass>   - Add entry")
        print("  get <master> <site>                 - Get entry (shows password)")
        print("  update <master> <id> password=<new> - Update entry")
        print("  delete <master> <id>                - Delete entry")
        print("  search <master> <query>             - Search entries")
        print("  generate [length] [--no-symbols]    - Generate password")
        print("  audit-weak <master>                 - Audit weak passwords")
        print("  audit-reused <master>               - Audit reused passwords")
        print("  export <master> <path.csv>          - Export vault to CSV")
        print("  stats <master>                      - Vault statistics")
        print("  demo                                - Demo vault with sample data")
        return

    cmd = args[0]

    if cmd == "init":
        if len(args) < 2:
            print("Usage: init <master_password>"); return
        db.init_vault(args[1])
        print("✓ Vault initialized")

    elif cmd == "add":
        if len(args) < 5:
            print("Usage: add <master> <site> <user> <pass>"); return
        if not db.unlock_vault(args[1]):
            print("✗ Wrong master password"); return
        entry = db.add_entry(args[2], args[3], args[4],
                             url=args[5] if len(args) > 5 else "")
        strength_label = "Weak" if entry.strength_score < 50 else "Medium" if entry.strength_score < 80 else "Strong"
        print(f"✓ Entry added: {entry.site} (ID: {entry.id})")
        print(f"  Strength: {entry.strength_score}/100 ({strength_label})")

    elif cmd == "get":
        if len(args) < 3:
            print("Usage: get <master> <site>"); return
        if not db.unlock_vault(args[1]):
            print("✗ Wrong master password"); return
        entry = db.get_entry(args[2])
        if not entry:
            print(f"✗ No entry found for '{args[2]}'"); return
        plain_pw = db.get_entry_password(args[2])
        print(f"  Site:     {entry.site}")
        print(f"  Username: {entry.username}")
        print(f"  Password: {plain_pw}")
        print(f"  URL:      {entry.url or 'N/A'}")
        print(f"  Strength: {entry.strength_score}/100")
        print(f"  Tags:     {', '.join(entry.tags) or 'none'}")

    elif cmd == "update":
        if len(args) < 4:
            print("Usage: update <master> <id> key=value ..."); return
        if not db.unlock_vault(args[1]):
            print("✗ Wrong master password"); return
        kwargs = {}
        for pair in args[3:]:
            k, _, v = pair.partition("=")
            kwargs[k] = v
        entry = db.update_entry(args[2], **kwargs)
        print(f"✓ Entry updated: {entry.site}" if entry else "✗ Entry not found")

    elif cmd == "delete":
        if len(args) < 3:
            print("Usage: delete <master> <id>"); return
        if not db.unlock_vault(args[1]):
            print("✗ Wrong master password"); return
        ok = db.delete_entry(args[2])
        print("✓ Entry deleted" if ok else "✗ Entry not found")

    elif cmd == "search":
        if len(args) < 3:
            print("Usage: search <master> <query>"); return
        if not db.unlock_vault(args[1]):
            print("✗ Wrong master password"); return
        results = db.search(args[2])
        print(f"Results for '{args[2]}': {len(results)}")
        for e in results:
            print(f"  [{e.strength_score:3d}] {e.site} — {e.username} ({e.url or 'no url'})")

    elif cmd == "generate":
        length = int(args[1]) if len(args) > 1 else 20
        no_symbols = "--no-symbols" in args
        pw = db.generate_password(length=length, symbols=not no_symbols)
        print(f"Generated: {pw}")
        print(f"Strength:  {_score_password(pw)}/100")

    elif cmd == "audit-weak":
        if len(args) < 2:
            print("Usage: audit-weak <master>"); return
        if not db.unlock_vault(args[1]):
            print("✗ Wrong master password"); return
        weak = db.audit_weak()
        print(f"Weak passwords: {len(weak)}")
        for e in weak:
            print(f"  [{e.strength_score:3d}] {e.site} — {e.username}")

    elif cmd == "audit-reused":
        if len(args) < 2:
            print("Usage: audit-reused <master>"); return
        if not db.unlock_vault(args[1]):
            print("✗ Wrong master password"); return
        groups = db.audit_reused()
        print(f"Reused password groups: {len(groups)}")
        for g in groups:
            sites = ", ".join(e.site for e in g)
            print(f"  Shared by: {sites}")

    elif cmd == "export":
        if len(args) < 3:
            print("Usage: export <master> <path.csv>"); return
        count = db.export_csv(args[1], args[2])
        print(f"✓ Exported {count} entries to {args[2]}")

    elif cmd == "stats":
        if len(args) < 2:
            print("Usage: stats <master>"); return
        if not db.unlock_vault(args[1]):
            print("✗ Wrong master password"); return
        s = db.vault_stats()
        print("Vault Stats:")
        print(f"  Total entries:    {s['total_entries']}")
        print(f"  Weak passwords:   {s['weak_passwords']}")
        print(f"  Strong passwords: {s['strong_passwords']}")
        print(f"  Avg strength:     {s['average_strength']:.1f}/100")
        print(f"  Reused groups:    {s['reused_groups']}")

    elif cmd == "demo":
        try:
            db.init_vault("DemoMaster123!")
        except RuntimeError:
            db.unlock_vault("DemoMaster123!")
        sample = [
            ("github.com", "dev@blackroad.io", "weak", "https://github.com"),
            ("gmail.com", "user@gmail.com", "abc123", "https://mail.google.com"),
            ("aws.amazon.com", "awsadmin", "P@ssw0rd!", "https://console.aws.amazon.com"),
            ("slack.com", "team@company.com", db.generate_password(24), "https://slack.com"),
            ("jira.atlassian.com", "admin@company.com", "weak", "https://jira.atlassian.com"),
        ]
        for site, user, pw, url in sample:
            db.add_entry(site, user, pw, url=url)
        print(f"✓ Demo vault created with {len(sample)} entries")
        s = db.vault_stats()
        print(f"  Weak: {s['weak_passwords']}, Reused groups: {s['reused_groups']}")
        print(f"  Avg strength: {s['average_strength']:.1f}/100")
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
