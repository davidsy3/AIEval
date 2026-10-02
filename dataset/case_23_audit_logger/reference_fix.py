"""Audit event store with a gzip export."""

import json
import sqlite3
import subprocess
import time

EVENTS = "audit_events"
FILTER_COLUMNS = ("actor", "action", "target")


def open_log(db_path=":memory:"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {EVENTS} ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, "
        "action TEXT NOT NULL, target TEXT, at REAL NOT NULL)"
    )
    conn.commit()
    return conn


def record(conn, actor, action, target=None, at=None):
    cur = conn.execute(
        f"INSERT INTO {EVENTS} (actor, action, target, at) VALUES (?, ?, ?, ?)",
        (actor, action, target, at if at is not None else time.time()),
    )
    conn.commit()
    return cur.lastrowid


def _where(filters):
    for key in filters:
        if key not in FILTER_COLUMNS:
            raise KeyError(key)
    keys = sorted(filters)
    parts = [f"{key} = ?" for key in keys]
    clause = " AND ".join(parts) if parts else "1=1"
    return clause, tuple(filters[key] for key in keys)


def search(conn, filters=None):
    where, params = _where(filters or {})
    rows = conn.execute(
        f"SELECT id, actor, action, target, at FROM {EVENTS} WHERE {where} ORDER BY id",
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def count_by_action(conn):
    rows = conn.execute(
        f"SELECT action, COUNT(*) AS n FROM {EVENTS} GROUP BY action ORDER BY action"
    ).fetchall()
    return {row["action"]: row["n"] for row in rows}


def recent(conn, limit=5):
    rows = conn.execute(
        f"SELECT id, actor, action FROM {EVENTS} ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(row) for row in rows]


def write_json(conn, path, filters=None):
    events = search(conn, filters)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(events, handle, sort_keys=True)
    return len(events)


def _export_cmd(source):
    return ["gzip", "-c", source]


def export_gzip(conn, path, dest=None, filters=None):
    count = write_json(conn, path, filters)
    dest = dest or f"{path}.gz"
    with open(dest, "wb") as archive:
        subprocess.run(_export_cmd(path), stdout=archive, check=True)
    return {"events": count, "archive": dest}
