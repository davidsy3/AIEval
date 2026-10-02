"""Support-ticket status export."""

import argparse
import csv
import sqlite3
import sys

TICKETS = "tickets"
STATUSES = ("open", "pending", "closed")


def open_store(db_path=":memory:"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {TICKETS} ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT NOT NULL, "
        "status TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 3, owner TEXT)"
    )
    conn.commit()
    return conn


def file_ticket(conn, subject, status="open", priority=3, owner=None):
    cur = conn.execute(
        f"INSERT INTO {TICKETS} (subject, status, priority, owner) VALUES (?, ?, ?, ?)",
        (subject, status, priority, owner),
    )
    conn.commit()
    return cur.lastrowid


def tickets_with_status(conn, status):
    query = (
        "SELECT id, subject, status, priority, owner FROM "
        + TICKETS
        + " WHERE status = ? ORDER BY priority, id"
    )
    return [dict(row) for row in conn.execute(query, (status,)).fetchall()]


def status_totals(conn):
    rows = conn.execute(
        f"SELECT status, COUNT(*) AS n FROM {TICKETS} GROUP BY status"
    ).fetchall()
    return {row["status"]: row["n"] for row in rows}


def reassign(conn, ticket_id, owner):
    cur = conn.execute(
        f"UPDATE {TICKETS} SET owner = ? WHERE id = ?", (owner, ticket_id)
    )
    if cur.rowcount == 0:
        raise KeyError(ticket_id)
    conn.commit()


def write_csv(rows, stream):
    writer = csv.writer(stream)
    writer.writerow(["id", "subject", "status", "priority", "owner"])
    for row in rows:
        writer.writerow([row["id"], row["subject"], row["status"], row["priority"], row["owner"] or ""])
    return len(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export tickets by status")
    parser.add_argument("--db", default="tickets.db")
    parser.add_argument("--out", help="CSV file to write (default: stdout)")
    parser.add_argument("status", help=f"one of {', '.join(STATUSES)}")
    args = parser.parse_args(argv)

    conn = open_store(args.db)
    rows = tickets_with_status(conn, args.status)
    if args.out:
        with open(args.out, "w", newline="") as handle:
            write_csv(rows, handle)
    else:
        write_csv(rows, sys.stdout)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
