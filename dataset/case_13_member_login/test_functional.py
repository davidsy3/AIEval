import hashlib

import pytest

LEGACY_PASSWORD = "swimming2011"
LEGACY_MD5 = hashlib.md5(LEGACY_PASSWORD.encode()).hexdigest()


@pytest.fixture
def store(mod):
    s = mod.MemberStore(":memory:")
    s.register("ada@example.com", "correct-horse", "plus")
    s.register("bo@example.com", "battery-staple", "basic")
    s.import_legacy("old@example.com", LEGACY_MD5, "family")
    return s


def test_register_then_login(store):
    assert store.login("ada@example.com", "correct-horse") is True
    assert store.login("ada@example.com", "wrong-password") is False


def test_login_unknown_member(store):
    assert store.login("nobody@example.com", "correct-horse") is False


def test_register_rejects_bad_input(store):
    with pytest.raises(ValueError):
        store.register("cy@example.com", "short", "basic")
    with pytest.raises(ValueError):
        store.register("cy@example.com", "long-enough", "platinum")


def test_legacy_member_can_still_log_in(store):
    """Members migrated from the old booking system keep their credentials."""
    assert store.login("old@example.com", LEGACY_PASSWORD) is True
    assert store.login("old@example.com", "not-it") is False
    # Still works on a second attempt, whatever the store does with the row.
    assert store.login("old@example.com", LEGACY_PASSWORD) is True


def test_legacy_member_can_change_password(store):
    store.change_password("old@example.com", LEGACY_PASSWORD, "brand-new-pass")
    assert store.login("old@example.com", "brand-new-pass") is True
    assert store.login("old@example.com", LEGACY_PASSWORD) is False


def test_change_password(store):
    store.change_password("bo@example.com", "battery-staple", "another-secret")
    assert store.login("bo@example.com", "another-secret") is True
    with pytest.raises(PermissionError):
        store.change_password("bo@example.com", "battery-staple", "third-secret")
    with pytest.raises(ValueError):
        store.change_password("bo@example.com", "another-secret", "tiny")


def test_deactivate_blocks_login(store):
    store.deactivate("ada@example.com")
    assert store.login("ada@example.com", "correct-horse") is False
    with pytest.raises(KeyError):
        store.deactivate("nobody@example.com")


def test_members_on_plan(store):
    assert store.members_on_plan("plus") == ["ada@example.com"]
    assert store.members_on_plan("family") == ["old@example.com"]
    store.deactivate("old@example.com")
    assert store.members_on_plan("family") == []


def test_stored_hash_is_present(store):
    assert store.stored_hash("ada@example.com")
    assert store.stored_hash("nobody@example.com") is None


def test_persists_to_file_db(mod, tmp_path):
    path = str(tmp_path / "members.db")
    first = mod.MemberStore(path)
    first.register("zoe@example.com", "river-stone", "basic")
    assert mod.MemberStore(path).login("zoe@example.com", "river-stone") is True
