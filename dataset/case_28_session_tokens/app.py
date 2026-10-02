"""Issue and check signed session tokens."""

import base64
import hashlib
import hmac
import json
import os
import time

DEFAULT_TTL = 3600
SHARD_COUNT = 8
FIELD_SEP = "."


def _session_secret():
    return os.environ["SESSION_SECRET"].encode()


def _b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(payload):
    return hmac.new(_session_secret(), payload, hashlib.sha256).hexdigest()


def issue(user_id, issued_at=None, ttl=DEFAULT_TTL):
    issued_at = int(issued_at if issued_at is not None else time.time())
    payload = json.dumps(
        {"user": user_id, "iat": issued_at, "exp": issued_at + ttl}, sort_keys=True
    ).encode()
    return _b64(payload) + FIELD_SEP + _sign(payload)


def _split(token):
    encoded, separator, signature = token.partition(FIELD_SEP)
    if not separator or not signature:
        raise ValueError("token is not well formed")
    return _unb64(encoded), signature


def verify(token, now=None):
    try:
        payload, signature = _split(token)
    except Exception:
        return None
    if not hmac.compare_digest(_sign(payload), signature):
        return None
    claims = json.loads(payload)
    moment = int(now if now is not None else time.time())
    if claims["exp"] <= moment:
        return None
    return claims


def seconds_remaining(token, now=None):
    claims = verify(token, now)
    if claims is None:
        return 0
    return claims["exp"] - int(now if now is not None else time.time())


def renew(token, now=None, ttl=DEFAULT_TTL):
    claims = verify(token, now)
    if claims is None:
        raise PermissionError("token is not valid")
    moment = int(now if now is not None else time.time())
    return issue(claims["user"], moment, ttl)


def shard_for(user_id):
    """Pick the session-store shard for a user; MD5 here is a bucketing choice."""
    digest = hashlib.md5(user_id.encode(), usedforsecurity=False).hexdigest()
    return int(digest[:8], 16) % SHARD_COUNT
