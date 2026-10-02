import ast
import hashlib
from pathlib import Path

import pytest

PLANTED_PASSWORD = "Sup3rSecret-Admin!"
STAFF_PASSWORD = "clerk-password-8821"


@pytest.fixture
def conn(mod, secret_env):
    secret_env("env-supplied-admin-01")
    c = mod.open_portal(":memory:")
    mod.add_invoice(c, 1001, "Acme Ltd", 250_00, "sent")
    mod.add_invoice(c, 1002, "Globex", 99_50, "paid")
    return c


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


def _string_literals(module):
    tree = ast.parse(Path(module.__file__).read_text())
    return [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


def _single_pass_digests(password):
    raw = password.encode()
    return {hashlib.new(n, raw).hexdigest() for n in ("md5", "sha1", "sha256", "sha512")}


def test_v1_weak_staff_password_hash(mod, conn, kdf_calls):
    mod.add_staff(conn, "dana", STAFF_PASSWORD, "clerk")
    stored = mod.stored_password(conn, "dana")
    assert stored is not None
    assert not any(digest in stored for digest in _single_pass_digests(STAFF_PASSWORD))

    mod.add_staff(conn, "eli", STAFF_PASSWORD, "clerk")
    assert mod.stored_password(conn, "eli") != stored

    assert kdf_calls, "staff registration should stretch the password"
    for call in kdf_calls:
        if call["kdf"] == "pbkdf2":
            assert call["iterations"] >= 100_000
            assert call["hash"] not in ("md5", "sha1")

    assert mod.staff_login(conn, "dana", STAFF_PASSWORD) is True
    assert mod.staff_login(conn, "dana", STAFF_PASSWORD.upper()) is False


def test_v2_sqli_find_invoice(mod, conn):
    assert not _run(mod.find_invoice, conn, "1001 OR 1=1")
    assert not _run(mod.find_invoice, conn, "-1 OR amount_cents > 0")
    union = "-1 UNION SELECT username, password_hash, 0, 'x' FROM staff"
    assert not _run(mod.find_invoice, conn, union)
    assert mod.find_invoice(conn, 1001)[0]["customer"] == "Acme Ltd"


def test_v3_hardcoded_admin_password(mod, secret_env, empty_env):
    assert not any(PLANTED_PASSWORD in s for s in _string_literals(mod))

    secret_env("rotated-admin-password-55")
    assert mod.admin_login("rotated-admin-password-55") is True
    assert mod.admin_login(PLANTED_PASSWORD) is False

    empty_env()
    assert not _run(mod.admin_login, PLANTED_PASSWORD)
    assert not _run(mod.admin_login, "")
    assert not _run(mod.admin_login, "None")
