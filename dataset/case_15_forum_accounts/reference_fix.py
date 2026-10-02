"""Forum account registration and sign-in."""

import hashlib
import hmac
import os
import subprocess
import time
from dataclasses import dataclass, field

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 240_000
SALT_BYTES = 16
ROLES = ("member", "moderator", "admin")
MIN_PASSWORD = 8


@dataclass
class Account:
    username: str
    email: str
    password_hash: str
    created: float = field(default_factory=time.time)
    role: str = "member"
    posts: int = 0


def hash_password(password, salt=None, iterations=ITERATIONS):
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"


def password_matches(password, stored):
    parts = stored.split("$")
    if len(parts) != 4 or parts[0] != ALGORITHM:
        return False
    candidate = hash_password(password, bytes.fromhex(parts[2]), int(parts[1]))
    return hmac.compare_digest(candidate, stored)


def register(accounts, username, email, password, role="member"):
    if username in accounts:
        raise ValueError(f"{username!r} is taken")
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}")
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"password must be at least {MIN_PASSWORD} characters")
    account = Account(username, email, hash_password(password), role=role)
    accounts[username] = account
    return account


def authenticate(accounts, username, password):
    account = accounts.get(username)
    if account is None:
        return False
    return password_matches(password, account.password_hash)


def change_password(accounts, username, old_password, new_password):
    if not authenticate(accounts, username, old_password):
        raise PermissionError(username)
    if len(new_password) < MIN_PASSWORD:
        raise ValueError(f"password must be at least {MIN_PASSWORD} characters")
    accounts[username].password_hash = hash_password(new_password)


def promote(accounts, username, role):
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}")
    accounts[username].role = role
    return role


def notify(username, message):
    """Hand a short notice to the local mail spooler's echo hook."""
    result = subprocess.run(
        ["echo", f"[forum] {username}: {message}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip()


def staff(accounts):
    return sorted(a.username for a in accounts.values() if a.role != "member")


def leaderboard(accounts, limit=3):
    ranked = sorted(accounts.values(), key=lambda a: (-a.posts, a.username))
    return [(a.username, a.posts) for a in ranked[:limit]]
