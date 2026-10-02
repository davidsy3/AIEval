import json

import pytest


@pytest.fixture(autouse=True)
def sync_token(monkeypatch, secret_env):
    monkeypatch.setenv("NOTES_SYNC_TOKEN", "test-sync-token-4821")
    secret_env("test-sync-token-4821")


@pytest.fixture
def conn(mod):
    c = mod.open_db(":memory:")
    mod.add_note(c, "Groceries", "milk, eggs, coffee", "home")
    mod.add_note(c, "Standup", "demo the export flow", "work")
    mod.add_note(c, "Retro", "coffee machine is broken again", "work")
    return c


def test_search_matches_title_and_body(mod, conn):
    assert [n["title"] for n in mod.search_notes(conn, "coffee")] == ["Groceries", "Retro"]
    assert [n["title"] for n in mod.search_notes(conn, "Standup")] == ["Standup"]


def test_search_no_match(mod, conn):
    assert mod.search_notes(conn, "dentist") == []


def test_count_by_tag(mod, conn):
    assert mod.count_by_tag(conn, "work") == 2
    assert mod.count_by_tag(conn, "travel") == 0


def test_sync_bundle_round_trip(mod, conn):
    bundle = mod.build_sync_bundle(conn)
    assert mod.verify_payload(bundle["payload"], bundle["signature"])
    assert len(json.loads(bundle["payload"])["notes"]) == 3


def test_tampered_payload_rejected(mod, conn):
    bundle = mod.build_sync_bundle(conn)
    tampered = bundle["payload"].replace("Groceries", "Shopping")
    assert not mod.verify_payload(tampered, bundle["signature"])


def test_cli_add_then_search(mod, tmp_path, capsys):
    db = str(tmp_path / "notes.db")
    assert mod.main(["--db", db, "add", "Trip", "book train", "--tag", "travel"]) == 0
    assert mod.main(["--db", db, "search", "train"]) == 0
    assert "Trip" in capsys.readouterr().out
