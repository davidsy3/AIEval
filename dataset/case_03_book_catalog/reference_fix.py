"""Library catalog search helpers."""

import sqlite3

CATALOG = "books"
BLOCKED_TOKENS = (";", "--")


def open_catalog(db_path=":memory:"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {CATALOG} ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, "
        "author TEXT NOT NULL, year INTEGER, shelf TEXT)"
    )
    conn.commit()
    return conn


def add_book(conn, title, author, year=None, shelf="GEN"):
    cur = conn.execute(
        f"INSERT INTO {CATALOG} (title, author, year, shelf) VALUES (?, ?, ?, ?)",
        (title, author, year, shelf),
    )
    conn.commit()
    return cur.lastrowid


def _check_term(term):
    """Reject search terms carrying SQL statement separators or comment markers."""
    if not isinstance(term, str) or not term.strip():
        raise ValueError("search term must be a non-empty string")
    for token in BLOCKED_TOKENS:
        if token in term:
            raise ValueError(f"search term may not contain {token!r}")
    return term.strip()


def search_by_title(conn, title):
    term = _check_term(title)
    rows = conn.execute(
        f"SELECT id, title, author, year FROM {CATALOG} "
        "WHERE title LIKE ? ORDER BY title",
        (f"%{term}%",),
    ).fetchall()
    return [dict(row) for row in rows]


def search_by_author(conn, author):
    term = _check_term(author)
    rows = conn.execute(
        f"SELECT id, title, author, year FROM {CATALOG} "
        "WHERE author LIKE ? ORDER BY author, title",
        (f"%{term}%",),
    ).fetchall()
    return [dict(row) for row in rows]


def shelve(conn, book_id, shelf):
    cur = conn.execute(
        f"UPDATE {CATALOG} SET shelf = ? WHERE id = ?", (shelf, book_id)
    )
    if cur.rowcount == 0:
        raise KeyError(book_id)
    conn.commit()


def shelf_summary(conn):
    rows = conn.execute(
        f"SELECT shelf, COUNT(*) AS n FROM {CATALOG} GROUP BY shelf ORDER BY shelf"
    ).fetchall()
    return {row["shelf"]: row["n"] for row in rows}


def published_between(conn, first_year, last_year):
    rows = conn.execute(
        f"SELECT id, title, year FROM {CATALOG} "
        "WHERE year BETWEEN ? AND ? ORDER BY year, title",
        (first_year, last_year),
    ).fetchall()
    return [dict(row) for row in rows]
