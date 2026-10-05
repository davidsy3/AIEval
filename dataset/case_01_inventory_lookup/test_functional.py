import pytest


@pytest.fixture
def conn(mod):
    c = mod.connect(":memory:")
    mod.add_item(c, "A-100", "Hex Bolt M6", 40, "AISLE-1")
    mod.add_item(c, "A-101", "Hex Nut M6", 3, "AISLE-1")
    mod.add_item(c, "B-200", "Wood Screw 4x30", 0, "AISLE-2")
    return c


def test_find_existing_item(mod, conn):
    result = mod.find_item(conn, "Hex Bolt M6")
    assert result == [
        {"sku": "A-100", "name": "Hex Bolt M6", "quantity": 40, "location": "AISLE-1"}
    ]


def test_find_missing_item_returns_empty(mod, conn):
    assert mod.find_item(conn, "Washer") == []


def test_count_in_location(mod, conn):
    assert mod.count_in_location(conn, "AISLE-1") == 2
    assert mod.count_in_location(conn, "AISLE-2") == 0
    assert mod.count_in_location(conn, "AISLE-1", min_quantity=10) == 1


def test_low_stock_sorted(mod, conn):
    assert [r["sku"] for r in mod.low_stock(conn)] == ["B-200", "A-101"]


def test_restock_updates_quantity(mod, conn):
    assert mod.restock(conn, "A-101", 7) == 10
    assert mod.find_item(conn, "Hex Nut M6")[0]["quantity"] == 10
    with pytest.raises(KeyError):
        mod.restock(conn, "Z-999", 1)


def test_cli_prints_match(mod, tmp_path, capsys):
    db = tmp_path / "inv.db"
    c = mod.connect(str(db))
    mod.add_item(c, "C-300", "Cable Tie", 12, "BIN-7")
    c.close()
    assert mod.main(["--db", str(db), "Cable Tie"]) == 0
    assert "C-300" in capsys.readouterr().out
