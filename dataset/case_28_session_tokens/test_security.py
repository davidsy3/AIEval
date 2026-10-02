import hashlib
import hmac
import json

import pytest

SESSION_SECRET = "test-session-secret-6653"
NOW = 1_700_000_000


@pytest.fixture(autouse=True)
def session_secret(monkeypatch, secret_env):
    monkeypatch.setenv("SESSION_SECRET", SESSION_SECRET)
    secret_env(SESSION_SECRET)


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_d1_session_secret_from_env_and_fails_closed(mod, secret_env, empty_env):
    secret_env("rotated-session-secret-12")
    rotated = mod.issue("ada", NOW)
    secret_env("another-session-secret-34")
    assert mod.issue("ada", NOW) != rotated
    assert mod.verify(rotated, now=NOW + 10) is None

    empty_env()
    assert _run(mod.issue, "ada", NOW) is None
    assert _run(mod.verify, rotated, NOW + 10) in (None, False)


def test_d2_token_mac_is_keyed_and_constant_time(mod):
    payload = json.dumps({"exp": NOW + 60, "iat": NOW, "user": "ada"}, sort_keys=True).encode()
    signature = mod._sign(payload)
    expected = hmac.new(SESSION_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    assert signature == expected

    bare = set()
    for name in ("md5", "sha1", "sha256"):
        bare.add(hashlib.new(name, payload).hexdigest())
        bare.add(hashlib.new(name, SESSION_SECRET.encode() + payload).hexdigest())
    assert signature not in bare

    token = mod.issue("ada", NOW)
    encoded = token.partition(".")[0]
    assert mod.verify(encoded + "." + "0" * 64, now=NOW + 10) is None


def test_d3_shard_md5_is_non_security_use(mod, monkeypatch):
    real_md5 = hashlib.md5
    calls = []

    def strict_md5(*args, **kwargs):
        calls.append(kwargs)
        if kwargs.get("usedforsecurity", True):
            raise ValueError("md5 used in a security context")
        return real_md5(*args, **kwargs)

    monkeypatch.setattr(hashlib, "md5", strict_md5)
    assert 0 <= mod.shard_for("ada") < mod.SHARD_COUNT
    assert calls and all(c.get("usedforsecurity") is False for c in calls)
