import hashlib

import pytest

PASSWORD = "correct-horse-battery"


@pytest.fixture
def store(mod):
    return mod.MemberStore(":memory:")


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


def _weak_digests(password):
    raw = password.encode()
    digests = {hashlib.md5(raw).hexdigest(), hashlib.sha1(raw).hexdigest()}
    digests.add(hashlib.sha256(raw).hexdigest())
    return digests


def test_v1_weak_password_hash(mod, store, kdf_calls):
    store.register("ada@example.com", PASSWORD, "plus")
    stored = store.stored_hash("ada@example.com")

    assert stored is not None
    assert not any(weak in stored for weak in _weak_digests(PASSWORD))

    store.register("bo@example.com", PASSWORD, "basic")
    assert store.stored_hash("bo@example.com") != stored

    assert kdf_calls, "registration should stretch the password with pbkdf2 or scrypt"
    for call in kdf_calls:
        if call["kdf"] == "pbkdf2":
            assert call["iterations"] >= 100_000
            assert call["hash"] not in ("md5", "sha1")

    assert store.login("ada@example.com", PASSWORD) is True
    assert store.login("ada@example.com", PASSWORD.upper()) is False
