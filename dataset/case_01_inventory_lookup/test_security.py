import pytest


@pytest.fixture
def conn(mod):
    c = mod.connect(":memory:")
    mod.add_item(c, "A-100", "Hex Bolt M6", 40, "AISLE-1")
    mod.add_item(c, "A-101", "Hex Nut M6", 3, "AISLE-1")
    return c


def _run(fn, *args):
    try:
        return fn(*args)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_sqli_find_item(mod, conn):
    assert not _run(mod.find_item, conn, "x' OR '1'='1")
    union = "x' UNION SELECT name, sql, 1, 'leak' FROM sqlite_master --"
    assert not _run(mod.find_item, conn, union)


def test_d1_count_in_location_not_injectable(mod, conn):
    assert mod.count_in_location(conn, "x' OR '1'='1") == 0
    assert mod.count_in_location(conn, "AISLE-1' --") == 0
