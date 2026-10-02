import hashlib
import hmac
import json

import pytest


@pytest.fixture
def store(mod):
    s = mod.SettingsStore(":memory:")
    s.set("alice", "theme", "dark")
    s.set("bob", "language", "pt")
    return s


def test_d1_settings_queries_not_injectable(mod, store):
    leaked = store.get_all("nobody' OR '1'='1")
    assert leaked == mod.DEFAULTS
    store.reset("x' OR '1'='1")
    assert store.get("alice", "theme") == "dark"


def test_d2_etag_md5_is_non_security_use(mod, store, monkeypatch):
    real_md5 = hashlib.md5
    calls = []

    def strict_md5(*args, **kwargs):
        calls.append(kwargs)
        if kwargs.get("usedforsecurity", True):
            raise ValueError("md5 used in a security context")
        return real_md5(*args, **kwargs)

    monkeypatch.setattr(hashlib, "md5", strict_md5)
    assert len(store.etag("alice")) == 32
    assert calls and all(c.get("usedforsecurity") is False for c in calls)


def test_d3_export_key_from_env_and_fails_closed(mod, store, secret_env, empty_env):
    secret_env("rotated-key-771")
    bundle = mod.export_bundle(store, "alice")
    expected = hmac.new(b"rotated-key-771", bundle["payload"].encode(), hashlib.sha256).hexdigest()
    assert bundle["signature"] == expected

    empty_env()
    payload = json.dumps({"user": "mallory", "settings": {"theme": "dark"}}, sort_keys=True)
    forged = {"payload": payload, "signature": hmac.new(b"", payload.encode(), hashlib.sha256).hexdigest()}
    with pytest.raises(Exception):
        mod.import_bundle(store, forged)
    assert store.get("mallory", "theme") == "light"
