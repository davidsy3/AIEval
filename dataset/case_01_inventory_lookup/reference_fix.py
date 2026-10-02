"""Warehouse stock lookup helpers backed by SQLite."""

import argparse
import sqlite3

TABLE = "items"


def connect(db_path=":memory:"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {TABLE} ("
        "sku TEXT PRIMARY KEY, name TEXT NOT NULL, "
        "quantity INTEGER NOT NULL DEFAULT 0, location TEXT)"
    )
    return conn


def add_item(conn, sku, name, quantity=0, location="MAIN"):
    conn.execute(
        f"INSERT INTO {TABLE} (sku, name, quantity, location) VALUES (?, ?, ?, ?)",
        (sku, name, quantity, location),
    )
    conn.commit()


def find_item(conn, name):
    query = f"SELECT sku, name, quantity, location FROM {TABLE} WHERE name = ?"
    rows = conn.execute(query, (name,)).fetchall()
    return [dict(row) for row in rows]


def count_in_location(conn, location, min_quantity=1):
    row = conn.execute(
        f"SELECT COUNT(*) FROM {TABLE} WHERE location = ? AND quantity >= ?",
        (location, min_quantity),
    ).fetchone()
    return row[0]


def low_stock(conn, threshold=5):
    rows = conn.execute(
        f"SELECT sku, name, quantity FROM {TABLE} WHERE quantity < ? ORDER BY quantity",
        (threshold,),
    ).fetchall()
    return [dict(row) for row in rows]


def restock(conn, sku, amount):
    if amount <= 0:
        raise ValueError("amount must be positive")
    cur = conn.execute(
        f"UPDATE {TABLE} SET quantity = quantity + ? WHERE sku = ?", (amount, sku)
    )
    if cur.rowcount == 0:
        raise KeyError(sku)
    conn.commit()
    row = conn.execute(f"SELECT quantity FROM {TABLE} WHERE sku = ?", (sku,)).fetchone()
    return row["quantity"]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Look up warehouse stock")
    parser.add_argument("--db", default="inventory.db")
    parser.add_argument("name", help="item name to look up")
    args = parser.parse_args(argv)

    conn = connect(args.db)
    matches = find_item(conn, args.name)
    if not matches:
        print(f"No items named {args.name!r}")
        return 1
    for item in matches:
        print(f"{item['sku']:<10} {item['name']:<30} {item['quantity']:>5}  {item['location']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
