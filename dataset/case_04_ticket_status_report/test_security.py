import pytest


@pytest.fixture
def conn(mod):
    c = mod.open_store(":memory:")
    mod.file_ticket(c, "Printer offline", "open", 2, "dana")
    mod.file_ticket(c, "Password reset", "closed", 3, "sam")
    return c


def _run(fn, *args):
    try:
        return fn(*args)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_sqli_tickets_with_status(mod, conn, tmp_path):
    assert not _run(mod.tickets_with_status, conn, "pending' OR '1'='1")
    union = "pending' UNION SELECT 1, name, sql, 1, 'x' FROM sqlite_master --"
    assert not _run(mod.tickets_with_status, conn, union)
    assert len(mod.tickets_with_status(conn, "open")) == 1

    db = str(tmp_path / "tickets.db")
    store = mod.open_store(db)
    mod.file_ticket(store, "Monitor flicker", "pending", 2, "ivo")
    mod.file_ticket(store, "Salary query", "closed", 1, "hr")
    store.close()
    out = tmp_path / "report.csv"
    _run(mod.main, ["--db", db, "--out", str(out), "pending' OR '1'='1"])
    assert "Salary query" not in (out.read_text() if out.exists() else "")
