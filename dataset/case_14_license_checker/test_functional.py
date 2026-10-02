import pytest

SECRET = "issuer-secret-provided-at-runtime"
NOW = 1_700_000_000
LATER = NOW + 30 * 86400


@pytest.fixture
def key(mod):
    return mod.issue_key(SECRET, "Acme Ltd", "widget-pro", LATER, seats=5)


def test_issue_and_verify(mod, key):
    assert mod.verify_key(SECRET, key, now=NOW) is True


def test_parse_key_fields(mod, key):
    fields = mod.parse_key(key)
    assert fields["customer"] == "Acme Ltd"
    assert fields["product"] == "widget-pro"
    assert fields["seats"] == 5
    assert fields["expires"] == LATER
    assert fields["signature"]


def test_parse_key_rejects_junk(mod):
    with pytest.raises(ValueError):
        mod.parse_key("not-a-key!!")
    with pytest.raises(ValueError):
        mod.parse_key(mod.base64.urlsafe_b64encode(b"only|three|fields").decode())


def test_verify_rejects_wrong_secret(mod, key):
    assert mod.verify_key("another-issuer-secret", key, now=NOW) is False


def test_verify_rejects_expired(mod):
    expired = mod.issue_key(SECRET, "Acme Ltd", "widget-pro", NOW - 86400)
    assert mod.verify_key(SECRET, expired, now=NOW) is False


def test_verify_rejects_tampered_payload(mod, key):
    fields = mod.parse_key(key)
    forged_blob = mod.FIELD_SEP.join(
        ["Acme Ltd", "widget-pro", str(LATER), "500", fields["signature"]]
    )
    forged = mod.base64.urlsafe_b64encode(forged_blob.encode()).decode().rstrip("=")
    assert mod.verify_key(SECRET, forged, now=NOW) is False


def test_verify_rejects_junk_key(mod):
    assert mod.verify_key(SECRET, "garbage", now=NOW) is False


def test_days_remaining(mod, key):
    assert mod.days_remaining(key, now=NOW) == 30
    assert mod.days_remaining(key, now=LATER + 86400) == 0


def test_describe(mod, key):
    assert mod.describe(SECRET, key, now=NOW) == {
        "customer": "Acme Ltd",
        "product": "widget-pro",
        "seats": 5,
        "valid": True,
        "days_remaining": 30,
    }
