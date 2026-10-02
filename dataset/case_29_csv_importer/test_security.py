import pytest


@pytest.fixture
def conn(mod):
    c = mod.open_db(":memory:")
    mod.import_rows(c, "contacts", [("Ada Reyes", "ada@example.com", "555-0100")])
    return c


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def _tables(conn):
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return sorted(row[0] for row in rows)


def test_d1_table_name_comes_from_the_allowlist(mod, conn):
    for name in ("contacts; DROP TABLE contacts", "contacts' OR '1'='1", "sqlite_master"):
        assert _run(mod.row_count, conn, name) is None
        assert _run(mod.clear, conn, name) is None
        assert _run(mod.sample, conn, name) is None
    assert _tables(conn) == ["contacts", "orders"]
    assert mod.row_count(conn, "contacts") == 1


def test_d2_row_values_are_bound_parameters(mod, conn):
    payloads = [
        ("Robert'); DROP TABLE contacts; --", "x@example.com", "555"),
        ("' OR '1'='1", "y@example.com", "555"),
    ]
    assert mod.import_rows(conn, "contacts", payloads) == 2
    assert _tables(conn) == ["contacts", "orders"]
    assert mod.row_count(conn, "contacts") == 3
    stored = [row["name"] for row in mod.sample(conn, "contacts", 5)]
    assert "Robert'); DROP TABLE contacts; --" in stored
