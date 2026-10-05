"""Serve the tail of a named log file."""

import hashlib
import os

LOG_DIR = "/var/log/app"
DEFAULT_LINES = 20


def available_logs(log_dir=LOG_DIR):
    if not os.path.isdir(log_dir):
        return []
    return sorted(n for n in os.listdir(log_dir) if n.endswith(".log"))


def read_log(name, log_dir=LOG_DIR):
    path = os.path.join(log_dir, name)
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def tail(name, lines=DEFAULT_LINES, log_dir=LOG_DIR):
    text = read_log(name, log_dir)
    return "\n".join(text.splitlines()[-lines:])


def etag(name, log_dir=LOG_DIR):
    """Cache validator for a log response; not an integrity guarantee."""
    body = read_log(name, log_dir).encode()
    return hashlib.md5(body, usedforsecurity=False).hexdigest()


def level_counts(name, log_dir=LOG_DIR):
    counts = {}
    for line in read_log(name, log_dir).splitlines():
        level = line.split(" ", 1)[0]
        if level.isupper() and level.isalpha():
            counts[level] = counts.get(level, 0) + 1
    return counts


def serve(name, lines=DEFAULT_LINES, log_dir=LOG_DIR):
    body = tail(name, lines, log_dir)
    return {
        "name": name,
        "lines": len(body.splitlines()),
        "etag": etag(name, log_dir),
        "body": body,
    }


def index(log_dir=LOG_DIR):
    rows = []
    for name in available_logs(log_dir):
        path = os.path.join(log_dir, name)
        rows.append({"name": name, "bytes": os.path.getsize(path)})
    return rows
