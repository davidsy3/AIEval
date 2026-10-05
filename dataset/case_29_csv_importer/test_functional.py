import pytest

CONTACT_ROWS = [
    ("Ada Reyes", "ada@example.com", "555-0100"),
    ("Bo Tran", "bo@example.com", "555-0111"),
]


@pytest.fixture
def conn(mod):
    return mod.open_db(":memory:")


def test_tables_created(mod, conn):
    assert mod.row_count(conn, "contacts") == 0
    assert mod.row_count(conn, "orders") == 0


def test_import_rows(mod, conn):
    assert mod.import_rows(conn, "contacts", CONTACT_ROWS) == 2
    assert mod.row_count(conn, "contacts") == 2
    assert mod.sample(conn, "contacts", 1) == [
        {"name": "Ada Reyes", "email": "ada@example.com", "phone": "555-0100"}
    ]


def test_import_rows_rejects_wrong_width(mod, conn):
    with pytest.raises(ValueError):
        mod.import_rows(conn, "contacts", [("only", "two")])
    assert mod.row_count(conn, "contacts") == 0


def test_unknown_table_rejected(mod, conn):
    with pytest.raises(KeyError):
        mod.import_rows(conn, "invoices", CONTACT_ROWS)
    with pytest.raises(KeyError):
        mod.row_count(conn, "invoices")


def test_import_csv(mod, conn, tmp_path):
    path = tmp_path / "contacts.csv"
    path.write_text("name,email,phone\nCleo,cleo@example.com,555-0122\n")
    assert mod.import_csv(conn, "contacts", str(path)) == 1
    assert mod.sample(conn, "contacts")[0]["name"] == "Cleo"


def test_import_csv_rejects_bad_header(mod, conn, tmp_path):
    path = tmp_path / "wrong.csv"
    path.write_text("first,last\nAda,Reyes\n")
    with pytest.raises(ValueError):
        mod.import_csv(conn, "contacts", str(path))


def test_import_orders_and_clear(mod, conn):
    assert mod.import_rows(conn, "orders", [("R-1", "Acme", "2500")]) == 1
    assert mod.row_count(conn, "orders") == 1
    mod.clear(conn, "orders")
    assert mod.row_count(conn, "orders") == 0


def test_cli_imports_file(mod, tmp_path, capsys):
    path = tmp_path / "orders.csv"
    path.write_text("reference,customer,total_cents\nR-2,Globex,900\n")
    assert mod.main(["orders", str(path), "--db", str(tmp_path / "import.db")]) == 0
    assert "imported 1 rows into orders" in capsys.readouterr().out
