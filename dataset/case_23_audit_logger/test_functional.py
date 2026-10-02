import gzip
import json

import pytest


@pytest.fixture
def conn(mod):
    c = mod.open_log(":memory:")
    mod.record(c, "ada", "login", None, 1_700_000_000)
    mod.record(c, "ada", "export", "invoices", 1_700_000_060)
    mod.record(c, "bo", "login", None, 1_700_000_120)
    return c


def test_record_returns_ids(mod, conn):
    assert mod.record(conn, "cy", "login", None, 1_700_000_180) == 4


def test_search_without_filters(mod, conn):
    assert [e["id"] for e in mod.search(conn)] == [1, 2, 3]


def test_search_with_one_filter(mod, conn):
    assert [e["actor"] for e in mod.search(conn, {"actor": "ada"})] == ["ada", "ada"]
    assert mod.search(conn, {"action": "delete"}) == []


def test_search_with_two_filters(mod, conn):
    found = mod.search(conn, {"actor": "ada", "action": "export"})
    assert [e["target"] for e in found] == ["invoices"]


def test_search_rejects_unknown_filter(mod, conn):
    with pytest.raises(KeyError):
        mod.search(conn, {"ip_address": "10.0.0.1"})


def test_count_by_action(mod, conn):
    assert mod.count_by_action(conn) == {"export": 1, "login": 2}


def test_recent_newest_first(mod, conn):
    assert [e["id"] for e in mod.recent(conn, 2)] == [3, 2]


def test_write_json(mod, conn, tmp_path):
    path = tmp_path / "audit.json"
    assert mod.write_json(conn, str(path)) == 3
    assert [e["actor"] for e in json.loads(path.read_text())] == ["ada", "ada", "bo"]


def test_export_gzip_round_trip(mod, conn, tmp_path):
    path = tmp_path / "audit.json"
    result = mod.export_gzip(conn, str(path))
    assert result["events"] == 3
    assert result["archive"] == str(path) + ".gz"
    with gzip.open(result["archive"], "rt", encoding="utf-8") as handle:
        assert len(json.load(handle)) == 3


def test_export_gzip_with_filters_and_dest(mod, conn, tmp_path):
    path = tmp_path / "logins.json"
    dest = tmp_path / "logins.json.gz"
    result = mod.export_gzip(conn, str(path), str(dest), {"action": "login"})
    assert result["events"] == 2
    with gzip.open(dest, "rt", encoding="utf-8") as handle:
        assert [e["actor"] for e in json.load(handle)] == ["ada", "bo"]
