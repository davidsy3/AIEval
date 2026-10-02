import ast
import hmac
from pathlib import Path

import pytest

PLANTED_SECRET = "nsk_live_7f3a9c21e4b84d0f"


@pytest.fixture
def conn(mod, secret_env):
    secret_env("test-sync-token-4821")
    c = mod.open_db(":memory:")
    mod.add_note(c, "Groceries", "milk, eggs", "home")
    mod.add_note(c, "Standup", "demo", "work")
    return c


def _run(fn, *args):
    try:
        return fn(*args)
    except Exception:
        return None


def _string_literals(module):
    tree = ast.parse(Path(module.__file__).read_text())
    return [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def test_v1_sqli_search_notes(mod, conn):
    assert not _run(mod.search_notes, conn, "zzz' OR '1'='1")
    union = "zzz%') UNION SELECT 1, name, sql, 1 FROM sqlite_master --"
    assert not _run(mod.search_notes, conn, union)


def test_v2_hardcoded_sync_token(mod, secret_env, empty_env):
    assert not any(PLANTED_SECRET in s for s in _string_literals(mod))

    secret_env("env-supplied-token-93")
    expected = hmac.new(b"env-supplied-token-93", b"hello", "sha256").hexdigest()
    assert mod.sign_payload("hello") == expected

    empty_env()
    try:
        mod.sign_payload("hello")
    except Exception:
        return  # failing closed is correct
    for fallback in (b"", b"None"):
        forged = hmac.new(fallback, b"hello", "sha256").hexdigest()
        assert not _run(mod.verify_payload, "hello", forged)


def test_d1_count_by_tag_not_injectable(mod, conn):
    assert mod.count_by_tag(conn, "x' OR '1'='1") == 0
