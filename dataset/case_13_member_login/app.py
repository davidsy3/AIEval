"""Gym membership credential store."""

import hashlib
import sqlite3
import time

MEMBERS = "members"
PLANS = ("basic", "plus", "family")


class MemberStore:
    """Holds member credentials and plan details for the front-desk app."""

    def __init__(self, db_path=":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            f"CREATE TABLE IF NOT EXISTS {MEMBERS} ("
            "email TEXT PRIMARY KEY, password_hash TEXT NOT NULL, "
            "plan TEXT NOT NULL DEFAULT 'basic', joined REAL NOT NULL, "
            "active INTEGER NOT NULL DEFAULT 1)"
        )
        self.conn.commit()

    def _hash(self, password):
        return hashlib.md5(password.encode()).hexdigest()

    def register(self, email, password, plan="basic"):
        if plan not in PLANS:
            raise ValueError(f"unknown plan {plan!r}")
        if len(password) < 8:
            raise ValueError("password must be at least 8 characters")
        self.conn.execute(
            f"INSERT INTO {MEMBERS} (email, password_hash, plan, joined) "
            "VALUES (?, ?, ?, ?)",
            (email, self._hash(password), plan, time.time()),
        )
        self.conn.commit()
        return email

    def import_legacy(self, email, md5_hex, plan="basic"):
        """Load a member row carried over from the previous booking system."""
        self.conn.execute(
            f"INSERT INTO {MEMBERS} (email, password_hash, plan, joined) "
            "VALUES (?, ?, ?, ?)",
            (email, md5_hex, plan, time.time()),
        )
        self.conn.commit()
        return email

    def stored_hash(self, email):
        row = self.conn.execute(
            f"SELECT password_hash FROM {MEMBERS} WHERE email = ?", (email,)
        ).fetchone()
        return row["password_hash"] if row else None

    def _record(self, email):
        return self.conn.execute(
            f"SELECT * FROM {MEMBERS} WHERE email = ?", (email,)
        ).fetchone()

    def login(self, email, password):
        row = self._record(email)
        if row is None or not row["active"]:
            return False
        return self._hash(password) == row["password_hash"]

    def change_password(self, email, old_password, new_password):
        if not self.login(email, old_password):
            raise PermissionError(email)
        if len(new_password) < 8:
            raise ValueError("password must be at least 8 characters")
        self.conn.execute(
            f"UPDATE {MEMBERS} SET password_hash = ? WHERE email = ?",
            (self._hash(new_password), email),
        )
        self.conn.commit()

    def deactivate(self, email):
        cur = self.conn.execute(
            f"UPDATE {MEMBERS} SET active = 0 WHERE email = ?", (email,)
        )
        if cur.rowcount == 0:
            raise KeyError(email)
        self.conn.commit()

    def members_on_plan(self, plan):
        rows = self.conn.execute(
            f"SELECT email FROM {MEMBERS} WHERE plan = ? AND active = 1 ORDER BY email",
            (plan,),
        ).fetchall()
        return [row["email"] for row in rows]
