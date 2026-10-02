"""Clinic appointment booking with staff sign-in."""

import hashlib
import hmac
import os
import sqlite3
from pathlib import Path

APPOINTMENTS = "appointments"
STAFF = "clinic_staff"
ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 240_000
SALT_BYTES = 16
ROLES = ("reception", "nurse", "doctor")


class ClinicBook:
    """Appointment book plus the credential store for clinic staff."""

    def __init__(self, db_path=":memory:", attachments_dir="attachments"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.attachments = Path(attachments_dir)
        self.conn.execute(
            f"CREATE TABLE IF NOT EXISTS {APPOINTMENTS} ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, patient TEXT NOT NULL, "
            "clinician TEXT NOT NULL, slot TEXT NOT NULL, reason TEXT, "
            "cancelled INTEGER NOT NULL DEFAULT 0)"
        )
        self.conn.execute(
            f"CREATE TABLE IF NOT EXISTS {STAFF} "
            "(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL)"
        )
        self.conn.commit()

    def book(self, patient, clinician, slot, reason=None):
        cur = self.conn.execute(
            f"INSERT INTO {APPOINTMENTS} (patient, clinician, slot, reason) "
            "VALUES (?, ?, ?, ?)",
            (patient, clinician, slot, reason),
        )
        self.conn.commit()
        return cur.lastrowid

    def appointments_for(self, patient):
        rows = self.conn.execute(
            f"SELECT id, clinician, slot, reason FROM {APPOINTMENTS} "
            "WHERE patient = ? AND cancelled = 0 ORDER BY slot",
            (patient,),
        ).fetchall()
        return [dict(row) for row in rows]

    def clinician_day(self, clinician, day):
        rows = self.conn.execute(
            f"SELECT id, patient, slot FROM {APPOINTMENTS} "
            "WHERE clinician = ? AND slot LIKE ? AND cancelled = 0 ORDER BY slot",
            (clinician, f"{day}%"),
        ).fetchall()
        return [dict(row) for row in rows]

    def cancel(self, appointment_id):
        cur = self.conn.execute(
            f"UPDATE {APPOINTMENTS} SET cancelled = 1 WHERE id = ?", (appointment_id,)
        )
        if cur.rowcount == 0:
            raise KeyError(appointment_id)
        self.conn.commit()

    def _hash_password(self, password, salt=None, iterations=ITERATIONS):
        if salt is None:
            salt = os.urandom(SALT_BYTES)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return f"{ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"

    def _password_matches(self, password, stored):
        parts = stored.split("$")
        if len(parts) != 4 or parts[0] != ALGORITHM:
            return False
        candidate = self._hash_password(password, bytes.fromhex(parts[2]), int(parts[1]))
        return hmac.compare_digest(candidate, stored)

    def register_staff(self, username, password, role="reception"):
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}")
        self.conn.execute(
            f"INSERT INTO {STAFF} (username, password_hash, role) VALUES (?, ?, ?)",
            (username, self._hash_password(password), role),
        )
        self.conn.commit()
        return username

    def stored_password(self, username):
        row = self.conn.execute(
            f"SELECT password_hash FROM {STAFF} WHERE username = ?", (username,)
        ).fetchone()
        return row["password_hash"] if row else None

    def staff_login(self, username, password):
        stored = self.stored_password(username)
        if stored is None:
            return False
        return self._password_matches(password, stored)

    def export_attachment(self, name):
        base = self.attachments.resolve()
        path = (base / name).resolve()
        if not path.is_relative_to(base):
            raise ValueError(f"{name!r} is outside the attachments directory")
        return path.read_bytes()
