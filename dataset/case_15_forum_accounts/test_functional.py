import pytest


@pytest.fixture
def accounts(mod):
    store = {}
    mod.register(store, "ada", "ada@example.com", "correct-horse")
    mod.register(store, "bo", "bo@example.com", "battery-staple", role="moderator")
    store["ada"].posts = 12
    store["bo"].posts = 4
    return store


def test_register_returns_account(mod, accounts):
    account = accounts["ada"]
    assert (account.username, account.email, account.role) == ("ada", "ada@example.com", "member")
    assert account.password_hash
    assert account.created > 0


def test_register_rejects_duplicates_and_bad_input(mod, accounts):
    with pytest.raises(ValueError):
        mod.register(accounts, "ada", "other@example.com", "long-enough")
    with pytest.raises(ValueError):
        mod.register(accounts, "cy", "cy@example.com", "short")
    with pytest.raises(ValueError):
        mod.register(accounts, "cy", "cy@example.com", "long-enough", role="owner")


def test_authenticate(mod, accounts):
    assert mod.authenticate(accounts, "ada", "correct-horse") is True
    assert mod.authenticate(accounts, "ada", "wrong-horse") is False
    assert mod.authenticate(accounts, "nobody", "correct-horse") is False


def test_change_password(mod, accounts):
    mod.change_password(accounts, "ada", "correct-horse", "another-secret")
    assert mod.authenticate(accounts, "ada", "another-secret") is True
    assert mod.authenticate(accounts, "ada", "correct-horse") is False
    with pytest.raises(PermissionError):
        mod.change_password(accounts, "ada", "correct-horse", "third-secret")
    with pytest.raises(ValueError):
        mod.change_password(accounts, "ada", "another-secret", "tiny")


def test_promote_and_staff(mod, accounts):
    assert mod.promote(accounts, "ada", "admin") == "admin"
    assert mod.staff(accounts) == ["ada", "bo"]
    with pytest.raises(ValueError):
        mod.promote(accounts, "ada", "owner")


def test_notify_echoes_message(mod):
    assert mod.notify("ada", "you have mail") == "[forum] ada: you have mail"


def test_leaderboard(mod, accounts):
    assert mod.leaderboard(accounts) == [("ada", 12), ("bo", 4)]
    assert mod.leaderboard(accounts, limit=1) == [("ada", 12)]
