"""Invoice lookup and staff sign-in for the billing portal."""

import hashlib
import hmac
import os
import sqlite3

INVOICES = "invoices"
STAFF = "staff"
STATUSES = ("draft", "sent", "paid", "void")
ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 240_000
SALT_BYTES = 16


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


def hash_password(password, salt=None, iterations=ITERATIONS):
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"


def password_matches(password, stored):
    parts = stored.split("$")
    if len(parts) != 4 or parts[0] != ALGORITHM:
        return False
    candidate = hash_password(password, bytes.fromhex(parts[2]), int(parts[1]))
    return hmac.compare_digest(candidate, stored)


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
    return password_matches(password, stored)


def _admin_password():
    return os.environ["BILLING_ADMIN_PASSWORD"]


def admin_login(password):
    return hmac.compare_digest(password, _admin_password())


def find_invoice(conn, invoice_id):
    cleaned = int(str(invoice_id).strip())
    rows = conn.execute(
        f"SELECT id, customer, amount_cents, status FROM {INVOICES} WHERE id = ?",
        (cleaned,),
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
