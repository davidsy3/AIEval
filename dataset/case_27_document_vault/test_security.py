import hashlib

import pytest

SHARE_PASSWORD = "share-password-4417"
SECRET = b"OTHER-OWNER-PRIVATE-9931"


@pytest.fixture
def vault(mod, tmp_path):
    v = mod.DocumentVault(str(tmp_path / "vault"))
    v.store("ada", "notes.txt", "quarterly notes")
    (tmp_path / "vault" / "bo").mkdir(parents=True, exist_ok=True)
    (tmp_path / "vault" / "bo" / "private.txt").write_bytes(SECRET)
    (tmp_path / "outside.txt").write_bytes(SECRET)
    return v


@pytest.fixture
def kdf_calls(mod, monkeypatch):
    """Record every password-stretching call, whichever name the module uses."""
    calls = []
    real_pbkdf2 = hashlib.pbkdf2_hmac
    real_scrypt = getattr(hashlib, "scrypt", None)

    def spy_pbkdf2(hash_name, password, salt, iterations, dklen=None):
        calls.append({"kdf": "pbkdf2", "hash": hash_name, "iterations": iterations})
        return real_pbkdf2(hash_name, password, salt, iterations, dklen)

    def spy_scrypt(password, **kwargs):
        calls.append({"kdf": "scrypt", "n": kwargs.get("n", 0)})
        return real_scrypt(password, **kwargs)

    for target in (hashlib, mod):
        if hasattr(target, "pbkdf2_hmac"):
            monkeypatch.setattr(target, "pbkdf2_hmac", spy_pbkdf2, raising=False)
        if real_scrypt is not None and hasattr(target, "scrypt"):
            monkeypatch.setattr(target, "scrypt", spy_scrypt, raising=False)
    return calls


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_d1_locate_stays_under_owner_folder(vault, tmp_path):
    for name in ("../bo/private.txt", "../../outside.txt", str(tmp_path / "outside.txt")):
        assert SECRET not in (_run(vault.fetch, "ada", name) or b"")
        assert _run(vault.store, "ada", name, b"overwritten") is None
    assert (tmp_path / "vault" / "bo" / "private.txt").read_bytes() == SECRET
    assert vault.fetch("ada", "notes.txt") == b"quarterly notes"


def test_d2_share_password_uses_slow_salted_kdf(vault, kdf_calls):
    vault.store("ada", "one.txt", "a", SHARE_PASSWORD)
    vault.store("ada", "two.txt", "b", SHARE_PASSWORD)
    rows = {d["name"] for d in vault.documents_for("ada")}
    assert {"one.txt", "two.txt"} <= rows

    stored = [
        vault.conn.execute(
            "SELECT share_hash FROM documents WHERE owner = ? AND name = ?", ("ada", name)
        ).fetchone()["share_hash"]
        for name in ("one.txt", "two.txt")
    ]
    assert stored[0] != stored[1]
    weak = {hashlib.new(n, SHARE_PASSWORD.encode()).hexdigest() for n in ("md5", "sha1", "sha256")}
    assert not any(digest in stored[0] for digest in weak)

    assert kdf_calls
    for call in kdf_calls:
        if call["kdf"] == "pbkdf2":
            assert call["iterations"] >= 100_000
            assert call["hash"] not in ("md5", "sha1")

    assert vault.unlock("ada", "one.txt", SHARE_PASSWORD) is True
    assert vault.unlock("ada", "one.txt", SHARE_PASSWORD.upper()) is False


def test_d3_document_queries_not_injectable(vault):
    assert vault.documents_for("ada' OR '1'='1") == []
    assert vault.total_bytes("ada' OR '1'='1") == 0
    assert _run(vault.unlock, "ada' OR '1'='1", "notes.txt", SHARE_PASSWORD) in (None, False)
    assert [d["name"] for d in vault.documents_for("ada")] == ["notes.txt"]
