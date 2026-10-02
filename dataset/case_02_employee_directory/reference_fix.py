"""Staff directory backed by SQLite."""

import sqlite3

STAFF_TABLE = "employees"
BANDS = {1: "Associate", 2: "Senior", 3: "Lead", 4: "Principal"}


class EmployeeDirectory:
    """Departmental lookups over the staff table."""

    def __init__(self, db_path=":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            f"CREATE TABLE IF NOT EXISTS {STAFF_TABLE} ("
            "badge TEXT PRIMARY KEY, name TEXT NOT NULL, department TEXT NOT NULL, "
            "title TEXT, band INTEGER NOT NULL DEFAULT 1)"
        )
        self.conn.commit()

    def hire(self, badge, name, department, band=1):
        self.conn.execute(
            f"INSERT INTO {STAFF_TABLE} (badge, name, department, title, band) "
            "VALUES (?, ?, ?, ?, ?)",
            (badge, name, department, BANDS[band], band),
        )
        self.conn.commit()

    def _where_clause(self, department):
        return "department = ?", (department,)

    def by_department(self, department):
        where, params = self._where_clause(department)
        rows = self.conn.execute(
            f"SELECT badge, name, title, band FROM {STAFF_TABLE} "
            f"WHERE {where} ORDER BY name",
            params,
        ).fetchall()
        return [dict(row) for row in rows]

    def headcount(self, department):
        row = self.conn.execute(
            f"SELECT COUNT(*) FROM {STAFF_TABLE} WHERE department = ?", (department,)
        ).fetchone()
        return row[0]

    def promote(self, badge):
        row = self.conn.execute(
            f"SELECT band FROM {STAFF_TABLE} WHERE badge = ?", (badge,)
        ).fetchone()
        if row is None:
            raise KeyError(badge)
        band = row["band"] + 1
        if band not in BANDS:
            raise ValueError(f"{badge} is already at the top band")
        self.conn.execute(
            f"UPDATE {STAFF_TABLE} SET band = ?, title = ? WHERE badge = ?",
            (band, BANDS[band], badge),
        )
        self.conn.commit()
        return BANDS[band]

    def transfer(self, badge, department):
        cur = self.conn.execute(
            f"UPDATE {STAFF_TABLE} SET department = ? WHERE badge = ?",
            (department, badge),
        )
        if cur.rowcount == 0:
            raise KeyError(badge)
        self.conn.commit()

    def departments(self):
        rows = self.conn.execute(
            f"SELECT department, COUNT(*) AS n FROM {STAFF_TABLE} "
            "GROUP BY department ORDER BY department"
        ).fetchall()
        return {row["department"]: row["n"] for row in rows}

    def close(self):
        self.conn.close()
