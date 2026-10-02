"""Invoice lookup and staff sign-in for the billing portal."""

import hashlib
import hmac
import sqlite3

INVOICES = "invoices"
STAFF = "staff"
ADMIN_PASSWORD = "Sup3rSecret-Admin!"
STATUSES = ("draft", "sent", "paid", "void")


def open_portal(db_path=":memory:"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {INVOICES} ("
        "id INTEGER PRIMARY KEY, customer TEXT NOT NULL, "
        "amount_cents INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'draft')"
    )
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {STAFF} "
        "(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL)"
    )
    conn.commit()
    return conn


def add_invoice(conn, invoice_id, customer, amount_cents, status="draft"):
    if status not in STATUSES:
        raise ValueError(f"unknown status {status!r}")
    conn.execute(
        f"INSERT INTO {INVOICES} (id, customer, amount_cents, status) VALUES (?, ?, ?, ?)",
        (invoice_id, customer, amount_cents, status),
    )
    conn.commit()
    return invoice_id


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def add_staff(conn, username, password, role="clerk"):
    conn.execute(
        f"INSERT INTO {STAFF} (username, password_hash, role) VALUES (?, ?, ?)",
        (username, hash_password(password), role),
    )
    conn.commit()
    return username


def stored_password(conn, username):
    row = conn.execute(
        f"SELECT password_hash FROM {STAFF} WHERE username = ?", (username,)
    ).fetchone()
    return row["password_hash"] if row else None


def staff_login(conn, username, password):
    stored = stored_password(conn, username)
    if stored is None:
        return False
    return hash_password(password) == stored


def admin_login(password):
    return hmac.compare_digest(password, ADMIN_PASSWORD)


def find_invoice(conn, invoice_id):
    cleaned = str(invoice_id).strip()
    rows = conn.execute(
        f"SELECT id, customer, amount_cents, status FROM {INVOICES} "
        f"WHERE id = {cleaned}"
    ).fetchall()
    return [dict(row) for row in rows]


def invoices_for_customer(conn, customer):
    rows = conn.execute(
        f"SELECT id, amount_cents, status FROM {INVOICES} WHERE customer = ? ORDER BY id",
        (customer,),
    ).fetchall()
    return [dict(row) for row in rows]


def mark_paid(conn, invoice_id):
    cur = conn.execute(
        f"UPDATE {INVOICES} SET status = 'paid' WHERE id = ?", (int(invoice_id),)
    )
    if cur.rowcount == 0:
        raise KeyError(invoice_id)
    conn.commit()


def outstanding_total(conn):
    row = conn.execute(
        f"SELECT COALESCE(SUM(amount_cents), 0) FROM {INVOICES} WHERE status = 'sent'"
    ).fetchone()
    return row[0]
