"""Per-user preference storage with signed export bundles."""

import hashlib
import hmac
import json
import os
import sqlite3

SETTINGS_TABLE = "user_settings"
DEFAULTS = {"theme": "light", "language": "en", "timezone": "UTC", "digest": "weekly"}


class SettingsStore:
    """Stores preference overrides per user; unset keys fall back to DEFAULTS."""

    def __init__(self, db_path=":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            f"CREATE TABLE IF NOT EXISTS {SETTINGS_TABLE} "
            "(user_id TEXT, key TEXT, value TEXT, PRIMARY KEY (user_id, key))"
        )

    def set(self, user_id, key, value):
        if key not in DEFAULTS:
            raise KeyError(key)
        self.conn.execute(
            f"INSERT OR REPLACE INTO {SETTINGS_TABLE} (user_id, key, value) VALUES (?, ?, ?)",
            (user_id, key, str(value)),
        )
        self.conn.commit()

    def get_all(self, user_id):
        rows = self.conn.execute(
            f"SELECT key, value FROM {SETTINGS_TABLE} WHERE user_id = ?", (user_id,)
        ).fetchall()
        merged = dict(DEFAULTS)
        merged.update(dict(rows))
        return merged

    def get(self, user_id, key):
        return self.get_all(user_id)[key]

    def reset(self, user_id):
        self.conn.execute(f"DELETE FROM {SETTINGS_TABLE} WHERE user_id = ?", (user_id,))
        self.conn.commit()

    def etag(self, user_id):
        body = json.dumps(self.get_all(user_id), sort_keys=True).encode()
        return hashlib.md5(body, usedforsecurity=False).hexdigest()


def _export_key():
    key = os.environ.get("SETTINGS_EXPORT_KEY")
    if not key:
        raise RuntimeError("SETTINGS_EXPORT_KEY is not configured")
    return key.encode()


def export_bundle(store, user_id):
    payload = json.dumps(
        {"user": user_id, "settings": store.get_all(user_id)}, sort_keys=True
    )
    signature = hmac.new(_export_key(), payload.encode(), hashlib.sha256).hexdigest()
    return {"payload": payload, "signature": signature}


def import_bundle(store, bundle):
    payload = bundle["payload"].encode()
    expected = hmac.new(_export_key(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, bundle.get("signature", "")):
        raise ValueError("bundle signature does not match")
    data = json.loads(payload)
    for key, value in data["settings"].items():
        if key in DEFAULTS:
            store.set(data["user"], key, value)
    return data["user"]
