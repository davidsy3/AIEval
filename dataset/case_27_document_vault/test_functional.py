import pytest

SHARE_PASSWORD = "share-password-4417"


@pytest.fixture
def vault(mod, tmp_path):
    v = mod.DocumentVault(str(tmp_path / "vault"))
    v.store("ada", "notes.txt", "quarterly notes")
    v.store("ada", "plan.txt", "the plan", SHARE_PASSWORD)
    v.store("bo", "notes.txt", "bo's notes")
    return v


def test_store_returns_name_and_writes_file(vault, tmp_path):
    assert vault.store("ada", "extra.txt", b"raw bytes") == "extra.txt"
    assert (tmp_path / "vault" / "ada" / "extra.txt").read_bytes() == b"raw bytes"


def test_store_in_subfolder(vault):
    vault.store("ada", "2026/q1.txt", "first quarter")
    assert vault.fetch("ada", "2026/q1.txt") == b"first quarter"


def test_fetch_keeps_owners_apart(vault):
    assert vault.fetch("ada", "notes.txt") == b"quarterly notes"
    assert vault.fetch("bo", "notes.txt") == b"bo's notes"


def test_fetch_missing_document(vault):
    with pytest.raises(Exception):
        vault.fetch("ada", "absent.txt")


def test_store_replaces_existing_row(vault):
    vault.store("ada", "notes.txt", "revised notes")
    assert vault.fetch("ada", "notes.txt") == b"revised notes"
    assert len(vault.documents_for("ada")) == 2


def test_unlock_share(vault):
    assert vault.unlock("ada", "plan.txt", SHARE_PASSWORD) is True
    assert vault.unlock("ada", "plan.txt", "wrong-password") is False
    assert vault.unlock("ada", "notes.txt", SHARE_PASSWORD) is False
    assert vault.unlock("nobody", "plan.txt", SHARE_PASSWORD) is False


def test_documents_for_and_totals(vault):
    assert vault.documents_for("ada") == [
        {"name": "notes.txt", "bytes": 15},
        {"name": "plan.txt", "bytes": 8},
    ]
    assert vault.total_bytes("ada") == 23
    assert vault.total_bytes("nobody") == 0


def test_remove(vault):
    vault.remove("ada", "plan.txt")
    assert [d["name"] for d in vault.documents_for("ada")] == ["notes.txt"]
    with pytest.raises(FileNotFoundError):
        vault.remove("ada", "plan.txt")
