"""Forum account registration and sign-in."""

import hashlib
import subprocess
import time
from dataclasses import dataclass, field

SITE_SALT = "forum-site-salt-2019"
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


def hash_password(password):
    return hashlib.sha256((SITE_SALT + password).encode()).hexdigest()


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
    return hash_password(password) == account.password_hash


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
