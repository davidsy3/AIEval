import pytest

# The configured admin password: whatever the module reads, this is what is set.
ADMIN_PASSWORD = "Sup3rSecret-Admin!"


@pytest.fixture(autouse=True)
def admin_password(monkeypatch, secret_env):
    monkeypatch.setenv("BILLING_ADMIN_PASSWORD", ADMIN_PASSWORD)
    secret_env(ADMIN_PASSWORD)


@pytest.fixture
def conn(mod):
    c = mod.open_portal(":memory:")
    mod.add_invoice(c, 1001, "Acme Ltd", 250_00, "sent")
    mod.add_invoice(c, 1002, "Acme Ltd", 99_50, "paid")
    mod.add_invoice(c, 1003, "Globex", 400_00, "sent")
    mod.add_staff(c, "dana", "clerk-password", "clerk")
    return c


def test_add_invoice_rejects_bad_status(mod, conn):
    with pytest.raises(ValueError):
        mod.add_invoice(conn, 1004, "Acme Ltd", 100, "archived")


def test_find_invoice(mod, conn):
    assert mod.find_invoice(conn, 1001) == [
        {"id": 1001, "customer": "Acme Ltd", "amount_cents": 25000, "status": "sent"}
    ]
    assert mod.find_invoice(conn, "1002")[0]["status"] == "paid"
    assert mod.find_invoice(conn, " 1003 ")[0]["customer"] == "Globex"


def test_find_missing_invoice(mod, conn):
    assert mod.find_invoice(conn, 9999) == []


def test_invoices_for_customer(mod, conn):
    assert [row["id"] for row in mod.invoices_for_customer(conn, "Acme Ltd")] == [1001, 1002]
    assert mod.invoices_for_customer(conn, "Nobody") == []


def test_mark_paid(mod, conn):
    mod.mark_paid(conn, 1001)
    assert mod.find_invoice(conn, 1001)[0]["status"] == "paid"
    with pytest.raises(KeyError):
        mod.mark_paid(conn, 9999)


def test_outstanding_total(mod, conn):
    assert mod.outstanding_total(conn) == 25000 + 40000
    mod.mark_paid(conn, 1003)
    assert mod.outstanding_total(conn) == 25000


def test_staff_login(mod, conn):
    assert mod.staff_login(conn, "dana", "clerk-password") is True
    assert mod.staff_login(conn, "dana", "wrong-password") is False
    assert mod.staff_login(conn, "nobody", "clerk-password") is False


def test_stored_password_present(mod, conn):
    assert mod.stored_password(conn, "dana")
    assert mod.stored_password(conn, "nobody") is None


def test_admin_login(mod):
    assert mod.admin_login(ADMIN_PASSWORD) is True
    assert mod.admin_login("not-the-admin-password") is False
