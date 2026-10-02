import pytest

SESSION_SECRET = "test-session-secret-6653"
NOW = 1_700_000_000


@pytest.fixture(autouse=True)
def session_secret(monkeypatch, secret_env):
    monkeypatch.setenv("SESSION_SECRET", SESSION_SECRET)
    secret_env(SESSION_SECRET)


@pytest.fixture
def token(mod):
    return mod.issue("ada", NOW)


def test_issue_then_verify(mod, token):
    claims = mod.verify(token, now=NOW + 10)
    assert claims["user"] == "ada"
    assert claims["iat"] == NOW
    assert claims["exp"] == NOW + mod.DEFAULT_TTL


def test_verify_rejects_expired(mod, token):
    assert mod.verify(token, now=NOW + mod.DEFAULT_TTL) is None


def test_verify_rejects_malformed(mod):
    assert mod.verify("not-a-token", now=NOW) is None
    assert mod.verify("", now=NOW) is None
    assert mod.verify("abc.def", now=NOW) is None


def test_verify_rejects_tampered_payload(mod, token):
    encoded, _, signature = token.partition(".")
    forged = mod._b64(b'{"exp": 99999999999, "iat": 0, "user": "root"}') + "." + signature
    assert mod.verify(forged, now=NOW) is None


def test_custom_ttl(mod):
    short = mod.issue("bo", NOW, ttl=60)
    assert mod.verify(short, now=NOW + 30)["user"] == "bo"
    assert mod.verify(short, now=NOW + 61) is None


def test_seconds_remaining(mod, token):
    assert mod.seconds_remaining(token, now=NOW) == mod.DEFAULT_TTL
    assert mod.seconds_remaining(token, now=NOW + mod.DEFAULT_TTL) == 0


def test_renew(mod, token):
    renewed = mod.renew(token, now=NOW + 100)
    assert mod.verify(renewed, now=NOW + 100)["iat"] == NOW + 100
    with pytest.raises(PermissionError):
        mod.renew(token, now=NOW + mod.DEFAULT_TTL)


def test_shard_for_is_stable_and_in_range(mod):
    assert mod.shard_for("ada") == mod.shard_for("ada")
    assert all(0 <= mod.shard_for(f"user-{i}") < mod.SHARD_COUNT for i in range(20))
