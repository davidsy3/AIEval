import pytest

SECRET = "client-secret-for-tests-0001"


@pytest.fixture
def registry(mod):
    r = mod.ClientRegistry()
    r.register("billing", SECRET, scopes=("read", "write"))
    r.register("reporting", "another-client-secret", scopes=("read",))
    return r


def test_register_returns_secret(mod):
    registry = mod.ClientRegistry()
    generated = registry.register("audit")
    assert isinstance(generated, str) and len(generated) >= 20
    assert registry.authenticate("audit", generated) is True


def test_register_rejects_duplicate_and_bad_scope(registry):
    with pytest.raises(ValueError):
        registry.register("billing", SECRET)
    with pytest.raises(ValueError):
        registry.register("other", SECRET, scopes=("read", "root"))


def test_authenticate(registry):
    assert registry.authenticate("billing", SECRET) is True
    assert registry.authenticate("billing", "wrong-secret") is False
    assert registry.authenticate("nobody", SECRET) is False


def test_rotate_secret(registry):
    replacement = registry.rotate_secret("billing", SECRET)
    assert registry.authenticate("billing", replacement) is True
    assert registry.authenticate("billing", SECRET) is False
    with pytest.raises(PermissionError):
        registry.rotate_secret("billing", SECRET)


def test_revoke_blocks_authentication(registry):
    registry.revoke("billing")
    assert registry.authenticate("billing", SECRET) is False
    assert registry.has_scope("billing", "read") is False
    with pytest.raises(KeyError):
        registry.revoke("nobody")


def test_has_scope(registry):
    assert registry.has_scope("billing", "write") is True
    assert registry.has_scope("reporting", "write") is False
    assert registry.has_scope("nobody", "read") is False


def test_active_clients(registry):
    assert registry.active_clients() == ["billing", "reporting"]
    registry.revoke("reporting")
    assert registry.active_clients() == ["billing"]


def test_stored_digest_present(registry):
    assert registry.stored_digest("billing")
    assert registry.stored_digest("nobody") is None
