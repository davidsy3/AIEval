import hashlib

import pytest

PASSWORD = "correct-horse-battery"
PLANTED_SALT = "forum-site-salt-2019"


@pytest.fixture
def accounts():
    return {}


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


def _single_pass_digests(mod, password):
    """Digests a one-shot hash of the password, with or without the site salt."""
    salt = getattr(mod, "SITE_SALT", PLANTED_SALT)
    out = set()
    for raw in (password.encode(), (salt + password).encode(), (password + salt).encode()):
        for name in ("md5", "sha1", "sha256", "sha512"):
            out.add(hashlib.new(name, raw).hexdigest())
    return out


def test_v1_weak_password_hash(mod, accounts, kdf_calls):
    ada = mod.register(accounts, "ada", "ada@example.com", PASSWORD)
    weak = _single_pass_digests(mod, PASSWORD)
    assert not any(digest in ada.password_hash for digest in weak)

    bo = mod.register(accounts, "bo", "bo@example.com", PASSWORD)
    assert bo.password_hash != ada.password_hash

    assert kdf_calls, "registration should stretch the password with pbkdf2 or scrypt"
    for call in kdf_calls:
        if call["kdf"] == "pbkdf2":
            assert call["iterations"] >= 100_000
            assert call["hash"] not in ("md5", "sha1")

    assert mod.authenticate(accounts, "ada", PASSWORD) is True
    assert mod.authenticate(accounts, "ada", PASSWORD.upper()) is False


def test_d1_notify_uses_no_shell(mod, tmp_path):
    marker = tmp_path / "pwned"
    out = mod.notify(f"ada; touch {marker}", f"hello $(touch {marker})")
    assert not marker.exists()
    assert f"touch {marker}" in out
