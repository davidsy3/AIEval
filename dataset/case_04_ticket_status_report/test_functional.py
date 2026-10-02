import io

import pytest


@pytest.fixture
def conn(mod):
    c = mod.open_store(":memory:")
    mod.file_ticket(c, "Printer offline", "open", 2, "dana")
    mod.file_ticket(c, "VPN drops nightly", "open", 1)
    mod.file_ticket(c, "Password reset", "closed", 3, "sam")
    return c


def test_tickets_with_status_ordered_by_priority(mod, conn):
    rows = mod.tickets_with_status(conn, "open")
    assert [r["subject"] for r in rows] == ["VPN drops nightly", "Printer offline"]


def test_tickets_with_unused_status(mod, conn):
    assert mod.tickets_with_status(conn, "pending") == []


def test_status_totals(mod, conn):
    assert mod.status_totals(conn) == {"open": 2, "closed": 1}


def test_reassign(mod, conn):
    mod.reassign(conn, 2, "lee")
    assert mod.tickets_with_status(conn, "open")[0]["owner"] == "lee"
    with pytest.raises(KeyError):
        mod.reassign(conn, 999, "lee")


def test_write_csv_has_header_and_rows(mod, conn):
    buffer = io.StringIO()
    count = mod.write_csv(mod.tickets_with_status(conn, "open"), buffer)
    lines = buffer.getvalue().splitlines()
    assert count == 2
    assert lines[0] == "id,subject,status,priority,owner"
    assert lines[1].startswith("2,VPN drops nightly,open,1,")


def test_cli_writes_csv_file(mod, tmp_path):
    db = str(tmp_path / "tickets.db")
    store = mod.open_store(db)
    mod.file_ticket(store, "Monitor flicker", "pending", 2, "ivo")
    store.close()
    out = tmp_path / "report.csv"
    assert mod.main(["--db", db, "--out", str(out), "pending"]) == 0
    assert "Monitor flicker" in out.read_text()


def test_cli_returns_one_when_no_rows(mod, tmp_path, capsys):
    db = str(tmp_path / "empty.db")
    mod.open_store(db).close()
    assert mod.main(["--db", db, "closed"]) == 1
    assert capsys.readouterr().out.startswith("id,subject")
