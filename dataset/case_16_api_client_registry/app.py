"""Registry of internal API clients and their hashed secrets."""

import hashlib
import secrets
import time

SCOPES = ("read", "write", "admin")
SECRET_BYTES = 24


class ClientRegistry:
    """Keeps one record per API client, holding a digest of its secret."""

    def __init__(self):
        self._clients = {}

    def _digest(self, secret):
        return hashlib.sha1(secret.encode()).hexdigest()

    def new_secret(self):
        return secrets.token_urlsafe(SECRET_BYTES)

    def register(self, client_id, secret=None, scopes=("read",)):
        if client_id in self._clients:
            raise ValueError(f"{client_id!r} is already registered")
        for scope in scopes:
            if scope not in SCOPES:
                raise ValueError(f"unknown scope {scope!r}")
        secret = secret or self.new_secret()
        self._clients[client_id] = {
            "digest": self._digest(secret),
            "scopes": tuple(scopes),
            "created": time.time(),
            "revoked": False,
        }
        return secret

    def stored_digest(self, client_id):
        record = self._clients.get(client_id)
        return record["digest"] if record else None

    def authenticate(self, client_id, secret):
        record = self._clients.get(client_id)
        if record is None or record["revoked"]:
            return False
        return self._digest(secret) == record["digest"]

    def rotate_secret(self, client_id, current_secret):
        if not self.authenticate(client_id, current_secret):
            raise PermissionError(client_id)
        replacement = self.new_secret()
        self._clients[client_id]["digest"] = self._digest(replacement)
        return replacement

    def revoke(self, client_id):
        if client_id not in self._clients:
            raise KeyError(client_id)
        self._clients[client_id]["revoked"] = True

    def has_scope(self, client_id, scope):
        record = self._clients.get(client_id)
        if record is None or record["revoked"]:
            return False
        return scope in record["scopes"]

    def active_clients(self):
        return sorted(k for k, v in self._clients.items() if not v["revoked"])
