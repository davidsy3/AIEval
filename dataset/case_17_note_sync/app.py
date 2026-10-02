"""Command-line notebook with signed export bundles for syncing."""

import argparse
import hmac
import json
import sqlite3
import time

NOTES_TABLE = "notes"
SYNC_TOKEN = "nsk_live_7f3a9c21e4b84d0f"


def open_db(path=":memory:"):
    conn = sqlite3.connect(path)
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {NOTES_TABLE} ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, "
        "body TEXT NOT NULL, tag TEXT, created REAL NOT NULL)"
    )
    return conn


def add_note(conn, title, body, tag=None):
    cur = conn.execute(
        f"INSERT INTO {NOTES_TABLE} (title, body, tag, created) VALUES (?, ?, ?, ?)",
        (title, body, tag, time.time()),
    )
    conn.commit()
    return cur.lastrowid


def _match_clause(term):
    return f"(title LIKE '%{term}%' OR body LIKE '%{term}%')"


def search_notes(conn, term):
    where = _match_clause(term)
    rows = conn.execute(
        f"SELECT id, title, body, tag FROM {NOTES_TABLE} WHERE {where} ORDER BY id"
    ).fetchall()
    return [{"id": r[0], "title": r[1], "body": r[2], "tag": r[3]} for r in rows]


def count_by_tag(conn, tag):
    row = conn.execute(
        f"SELECT COUNT(*) FROM {NOTES_TABLE} WHERE tag = ?", (tag,)
    ).fetchone()
    return row[0]


def export_payload(conn):
    rows = conn.execute(
        f"SELECT id, title, body, tag FROM {NOTES_TABLE} ORDER BY id"
    ).fetchall()
    notes = [{"id": r[0], "title": r[1], "body": r[2], "tag": r[3]} for r in rows]
    return json.dumps({"notes": notes}, sort_keys=True)


def sign_payload(payload):
    return hmac.new(SYNC_TOKEN.encode(), payload.encode(), "sha256").hexdigest()


def verify_payload(payload, signature):
    return hmac.compare_digest(sign_payload(payload), signature)


def build_sync_bundle(conn):
    payload = export_payload(conn)
    return {"payload": payload, "signature": sign_payload(payload)}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="notes")
    parser.add_argument("--db", default="notes.db")
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add")
    add.add_argument("title")
    add.add_argument("body")
    add.add_argument("--tag")

    find = sub.add_parser("search")
    find.add_argument("term")

    sub.add_parser("export")

    args = parser.parse_args(argv)
    conn = open_db(args.db)

    if args.command == "add":
        note_id = add_note(conn, args.title, args.body, args.tag)
        print(f"Added note {note_id}")
    elif args.command == "search":
        for note in search_notes(conn, args.term):
            print(f"[{note['id']}] {note['title']}")
    elif args.command == "export":
        print(json.dumps(build_sync_bundle(conn)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
