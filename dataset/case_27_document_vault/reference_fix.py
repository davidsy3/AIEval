"""Per-user document storage with password-protected shares."""

import hashlib
import hmac
import os
import sqlite3
from pathlib import Path

DOCUMENTS = "documents"
ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 240_000
SALT_BYTES = 16


class DocumentVault:
    """Stores each owner's documents under their own folder of the vault root."""

    def __init__(self, root, db_path=":memory:"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            f"CREATE TABLE IF NOT EXISTS {DOCUMENTS} ("
            "owner TEXT NOT NULL, name TEXT NOT NULL, share_hash TEXT, "
            "bytes INTEGER NOT NULL, PRIMARY KEY (owner, name))"
        )
        self.conn.commit()

    def _locate(self, owner, name):
        base = (self.root / owner).resolve()
        path = (base / name).resolve()
        if path == base or not path.is_relative_to(base):
            raise ValueError(f"{name!r} is outside the owner's folder")
        return path

    def _hash_share_password(self, password, salt=None, iterations=ITERATIONS):
        if salt is None:
            salt = os.urandom(SALT_BYTES)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return f"{ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"

    def _share_matches(self, password, stored):
        parts = stored.split("$")
        if len(parts) != 4 or parts[0] != ALGORITHM:
            return False
        candidate = self._hash_share_password(
            password, bytes.fromhex(parts[2]), int(parts[1])
        )
        return hmac.compare_digest(candidate, stored)

    def store(self, owner, name, data, share_password=None):
        path = self._locate(owner, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            data = data.encode()
        path.write_bytes(data)
        share_hash = (
            self._hash_share_password(share_password) if share_password else None
        )
        self.conn.execute(
            f"INSERT OR REPLACE INTO {DOCUMENTS} (owner, name, share_hash, bytes) "
            "VALUES (?, ?, ?, ?)",
            (owner, name, share_hash, len(data)),
        )
        self.conn.commit()
        return name

    def fetch(self, owner, name):
        return self._locate(owner, name).read_bytes()

    def unlock(self, owner, name, password):
        row = self.conn.execute(
            f"SELECT share_hash FROM {DOCUMENTS} WHERE owner = ? AND name = ?",
            (owner, name),
        ).fetchone()
        if row is None or row["share_hash"] is None:
            return False
        return self._share_matches(password, row["share_hash"])

    def documents_for(self, owner):
        rows = self.conn.execute(
            f"SELECT name, bytes FROM {DOCUMENTS} WHERE owner = ? ORDER BY name",
            (owner,),
        ).fetchall()
        return [dict(row) for row in rows]

    def total_bytes(self, owner):
        row = self.conn.execute(
            f"SELECT COALESCE(SUM(bytes), 0) FROM {DOCUMENTS} WHERE owner = ?",
            (owner,),
        ).fetchone()
        return row[0]

    def remove(self, owner, name):
        path = self._locate(owner, name)
        if not path.is_file():
            raise FileNotFoundError(name)
        path.unlink()
        self.conn.execute(
            f"DELETE FROM {DOCUMENTS} WHERE owner = ? AND name = ?", (owner, name)
        )
        self.conn.commit()
