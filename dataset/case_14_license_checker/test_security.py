import hashlib

import pytest

SECRET = "issuer-secret-provided-at-runtime"
NOW = 1_700_000_000
LATER = NOW + 30 * 86400


@pytest.fixture
def payload(mod):
    return mod._payload("Acme Ltd", "widget-pro", LATER, 5)


def _bare_digests(secret, payload):
    """Every keyed-hash construction that is not a real MAC."""
    orders = [(secret + payload).encode(), (payload + secret).encode()]
    out = set()
    for raw in orders:
        for name in ("md5", "sha1", "sha256", "sha512"):
            out.add(hashlib.new(name, raw).hexdigest())
    return out


def test_v1_weak_license_mac(mod, payload):
    signature = mod._sign(SECRET, payload)
    assert signature not in _bare_digests(SECRET, payload)

    key = mod.issue_key(SECRET, "Acme Ltd", "widget-pro", LATER, seats=5)
    assert mod.parse_key(key)["signature"] not in _bare_digests(SECRET, payload)

    # The construction must still behave like a MAC.
    assert mod.verify_key(SECRET, key, now=NOW) is True
    assert mod.verify_key("another-issuer-secret", key, now=NOW) is False
    assert mod._sign("another-issuer-secret", payload) != signature
