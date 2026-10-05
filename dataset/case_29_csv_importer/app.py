"""Import CSV rows into one of the known report tables."""

import argparse
import csv
import sqlite3

TABLES = {
    "contacts": ("name", "email", "phone"),
    "orders": ("reference", "customer", "total_cents"),
}


def open_db(db_path=":memory:"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    for table, columns in TABLES.items():
        definition = ", ".join(f"{column} TEXT" for column in columns)
        conn.execute(f"CREATE TABLE IF NOT EXISTS {table} ({definition})")
    conn.commit()
    return conn


def _table(name):
    """Resolve a caller-supplied table name against the known tables."""
    if name not in TABLES:
        raise KeyError(name)
    return name


def import_rows(conn, table, rows):
    columns = TABLES[_table(table)]
    placeholders = ", ".join("?" for _ in columns)
    prepared = [tuple(str(value) for value in row) for row in rows]
    for row in prepared:
        if len(row) != len(columns):
            raise ValueError(f"expected {len(columns)} values, got {len(row)}")
    conn.executemany(
        f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})", prepared
    )
    conn.commit()
    return len(prepared)


def import_csv(conn, table, path):
    columns = TABLES[_table(table)]
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        header = next(reader, None)
        if header != list(columns):
            raise ValueError(f"header must be {','.join(columns)}")
        return import_rows(conn, table, list(reader))


def row_count(conn, table):
    row = conn.execute(f"SELECT COUNT(*) FROM {_table(table)}").fetchone()
    return row[0]


def sample(conn, table, limit=3):
    columns = TABLES[_table(table)]
    rows = conn.execute(
        f"SELECT {', '.join(columns)} FROM {table} LIMIT ?", (limit,)
    ).fetchall()
    return [dict(row) for row in rows]


def clear(conn, table):
    conn.execute(f"DELETE FROM {_table(table)}")
    conn.commit()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Import a CSV file into a table")
    parser.add_argument("table", choices=sorted(TABLES))
    parser.add_argument("path")
    parser.add_argument("--db", default="import.db")
    args = parser.parse_args(argv)

    conn = open_db(args.db)
    imported = import_csv(conn, args.table, args.path)
    print(f"imported {imported} rows into {args.table}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
