import pytest


@pytest.fixture
def conn(mod):
    c = mod.open_catalog(":memory:")
    mod.add_book(c, "The Long Winter", "Ana Cruz", 1998, "FIC")
    mod.add_book(c, "Bridge Design Basics", "Piet Okonjo", 2011, "TEC")
    return c


def _run(fn, *args):
    try:
        return fn(*args)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_sqli_search_by_title(mod, conn):
    # Neither payload contains a blocked token.
    assert not _run(mod.search_by_title, conn, "zzz%' OR '1'='1' OR title LIKE '%")
    union = "zzz%' UNION SELECT 1, name, sql, 1 FROM sqlite_master WHERE type LIKE '%table"
    assert not _run(mod.search_by_title, conn, union)
    assert [b["title"] for b in mod.search_by_title(conn, "Winter")] == ["The Long Winter"]


def test_d1_search_by_author_not_injectable(mod, conn):
    assert mod.search_by_author(conn, "zzz' OR '1'='1") == []
    assert mod.search_by_author(conn, "Cruz%' OR 'x'='x") == []
