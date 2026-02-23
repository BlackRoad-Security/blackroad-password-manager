"""Tests for BlackRoad Password Manager."""
import pytest
from password_manager import (
    PasswordManager, encrypt, decrypt, _score_password, _derive_key
)


MASTER = "TestMaster#2024!"


@pytest.fixture
def pm(tmp_path):
    mgr = PasswordManager(db_path=str(tmp_path / "vault_test.db"))
    mgr.init_vault(MASTER)
    return mgr


def test_init_vault(tmp_path):
    mgr = PasswordManager(db_path=str(tmp_path / "v.db"))
    ok = mgr.init_vault("TestPass123!")
    assert ok is True


def test_init_vault_duplicate_raises(pm, tmp_path):
    with pytest.raises(RuntimeError, match="already initialised"):
        pm.init_vault("AnotherPass!")


def test_unlock_correct_password(tmp_path):
    mgr = PasswordManager(db_path=str(tmp_path / "v2.db"))
    mgr.init_vault("CorrectPass!")
    mgr2 = PasswordManager(db_path=str(tmp_path / "v2.db"))
    assert mgr2.unlock_vault("CorrectPass!") is True


def test_unlock_wrong_password(tmp_path):
    mgr = PasswordManager(db_path=str(tmp_path / "v3.db"))
    mgr.init_vault("RightPass!")
    mgr2 = PasswordManager(db_path=str(tmp_path / "v3.db"))
    assert mgr2.unlock_vault("WrongPass!") is False


def test_unlock_not_initialized_raises(tmp_path):
    mgr = PasswordManager(db_path=str(tmp_path / "empty.db"))
    with pytest.raises(RuntimeError, match="not initialised"):
        mgr.unlock_vault("pass")


def test_add_entry(pm):
    entry = pm.add_entry("github.com", "user@test.com", "SecureP@ss123!")
    assert entry.site == "github.com"
    assert entry.username == "user@test.com"
    assert entry.strength_score > 0


def test_add_entry_requires_unlock():
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        mgr = PasswordManager(db_path=f.name)
        with pytest.raises(RuntimeError, match="locked"):
            mgr.add_entry("site", "user", "pass")


def test_get_entry(pm):
    pm.add_entry("slack.com", "alice", "P@ssw0rd!")
    entry = pm.get_entry("slack")
    assert entry is not None
    assert "slack" in entry.site


def test_get_entry_not_found(pm):
    assert pm.get_entry("nonexistent-site-xyz") is None


def test_get_entry_password(pm):
    original_pw = "MySecret#2024@"
    pm.add_entry("example.com", "bob", original_pw)
    retrieved = pm.get_entry_password("example.com")
    assert retrieved == original_pw


def test_update_entry_password(pm):
    entry = pm.add_entry("amazon.com", "carol", "OldP@ss!")
    updated = pm.update_entry(entry.id, password="NewP@ss#99!")
    assert updated is not None
    new_pw = pm.get_entry_password("amazon.com")
    assert new_pw == "NewP@ss#99!"


def test_update_entry_site(pm):
    entry = pm.add_entry("old-site.com", "user", "Pass#1!")
    updated = pm.update_entry(entry.id, site="new-site.com")
    assert updated.site == "new-site.com"


def test_update_nonexistent(pm):
    result = pm.update_entry("nonexistent-id", site="x.com")
    assert result is None


def test_delete_entry(pm):
    entry = pm.add_entry("delete-me.com", "user", "Pass!")
    ok = pm.delete_entry(entry.id)
    assert ok is True
    assert pm.get_entry("delete-me.com") is None


def test_delete_nonexistent(pm):
    assert pm.delete_entry("nonexistent-id") is False


def test_search(pm):
    pm.add_entry("google.com", "user@google.com", "GPass!")
    pm.add_entry("gmail.com", "user2@gmail.com", "GPass2!")
    pm.add_entry("github.com", "dev", "DevPass!")
    results = pm.search("gmail")
    assert len(results) >= 1
    assert any("gmail" in e.site for e in results)


def test_generate_password_length(pm):
    pw = pm.generate_password(length=20)
    assert len(pw) == 20


def test_generate_password_unique(pm):
    pw1 = pm.generate_password(20)
    pw2 = pm.generate_password(20)
    assert pw1 != pw2


def test_generate_password_no_symbols(pm):
    pw = pm.generate_password(16, symbols=False)
    assert len(pw) == 16
    import string
    assert not any(c in "!@#$%^&*()" for c in pw)


def test_score_weak():
    assert _score_password("abc") < 50


def test_score_strong():
    assert _score_password("MyStr0ng#Pass!X9") >= 80


def test_audit_weak(pm):
    pm.add_entry("site1.com", "u1", "weak")
    pm.add_entry("site2.com", "u2", "AlsoWeak")
    pm.add_entry("site3.com", "u3", "Str0ng#Pass!2024")
    weak = pm.audit_weak(threshold=50)
    weak_sites = [e.site for e in weak]
    assert "site1.com" in weak_sites


def test_audit_reused(pm):
    same_pw = "ReusedP@ss!"
    pm.add_entry("site-a.com", "u1", same_pw)
    pm.add_entry("site-b.com", "u2", same_pw)
    pm.add_entry("site-c.com", "u3", "UniqueP@ss!")
    groups = pm.audit_reused()
    assert len(groups) >= 1
    assert len(groups[0]) == 2


def test_audit_reused_no_reuse(pm):
    pm.add_entry("only-site.com", "u1", "Unique#Pass1!")
    groups = pm.audit_reused()
    assert len(groups) == 0


def test_export_csv(pm, tmp_path):
    pm.add_entry("export-test.com", "user", "P@ssw0rd!")
    out = tmp_path / "export.csv"
    count = pm.export_csv(MASTER, str(out))
    assert count >= 1
    assert out.exists()
    content = out.read_text()
    assert "export-test.com" in content
    assert "P@ssw0rd!" in content


def test_export_csv_wrong_password(pm, tmp_path):
    out = tmp_path / "export.csv"
    with pytest.raises(PermissionError):
        pm.export_csv("WrongMaster!", str(out))


def test_vault_stats(pm):
    pm.add_entry("s1.com", "u1", "weak")
    pm.add_entry("s2.com", "u2", "Str0ng#Pass!99!")
    s = pm.vault_stats()
    assert s["total_entries"] == 2
    assert "weak_passwords" in s
    assert "average_strength" in s


def test_encrypt_decrypt_roundtrip():
    plain = "Hello, SecretWorld! 🔒"
    master = "TestMasterKey123!"
    ciphertext = encrypt(plain, master)
    assert ciphertext != plain
    decrypted = decrypt(ciphertext, master)
    assert decrypted == plain


def test_encrypt_different_each_time():
    plain = "same plaintext"
    master = "masterpass"
    c1 = encrypt(plain, master)
    c2 = encrypt(plain, master)
    assert c1 != c2  # Different random salts


def test_entry_strength_score(pm):
    weak = pm.add_entry("weak-site.com", "u", "abc")
    strong = pm.add_entry("strong-site.com", "u", "V3ryStr0ng#Pass!XZ")
    assert weak.strength_score < strong.strength_score
