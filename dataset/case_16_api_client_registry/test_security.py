import hashlib

import pytest

SECRET = "client-secret-for-tests-0001"


@pytest.fixture
def registry(mod):
    return mod.ClientRegistry()


@pytest.fixture
def kdf_calls(mod, monkeypatch):
    """Record every secret-stretching call, whichever name the module uses."""
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


def _single_pass_digests(secret):
    raw = secret.encode()
    return {hashlib.new(name, raw).hexdigest() for name in ("md5", "sha1", "sha256", "sha512")}


def test_v1_weak_secret_digest(registry, kdf_calls):
    registry.register("billing", SECRET, scopes=("read", "write"))
    stored = registry.stored_digest("billing")
    assert stored is not None
    assert not any(digest in stored for digest in _single_pass_digests(SECRET))

    registry.register("reporting", SECRET, scopes=("read",))
    assert registry.stored_digest("reporting") != stored

    assert kdf_calls, "registration should stretch the secret with pbkdf2 or scrypt"
    for call in kdf_calls:
        if call["kdf"] == "pbkdf2":
            assert call["iterations"] >= 100_000
            assert call["hash"] not in ("md5", "sha1")

    assert registry.authenticate("billing", SECRET) is True
    assert registry.authenticate("billing", SECRET.upper()) is False
