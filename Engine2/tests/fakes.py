"""
FakeLLM: canned model replies, so every stage can be tested with no API key.
===========================================================================

Each stage owner can test their own stage without the others working:

    llm = FakeLLM(["VERDICT: NOT VULNERABLE\\nWHAT: ...\\nWHY: n/a\\nEXPLOIT: n/a"])
    triaged = triage(case, findings, llm, CONFIG)

Replies are consumed in order; the last one repeats. Pass a callable to decide
the reply from the prompt, or an exception instance to make the call fail.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Sequence

from config import CONFIG, Config
from llm import LLM
from models import Annotation, Case


class FakeLLM(LLM):
    """An LLM that returns what you told it to. `offline` is False: stages call it."""

    offline = False

    def __init__(self,
                 replies: Sequence[str | Exception] | Callable[[str, str], str],
                 cfg: Config = CONFIG) -> None:
        super().__init__(cfg)
        self._replies = replies
        self.prompts: list[tuple[str, str]] = []   # (system, user) per call

    def complete(self, system: str, user: str, max_tokens: int | None = None) -> str:
        self.calls += 1
        self.prompts.append((system, user))
        if callable(self._replies):
            return self._replies(system, user)
        if not self._replies:
            return ""
        index = min(self.calls - 1, len(self._replies) - 1)
        reply = self._replies[index]
        if isinstance(reply, Exception):
            raise reply
        return reply

    @property
    def last_user_message(self) -> str:
        return self.prompts[-1][1] if self.prompts else ""


# --- hand-made inputs --------------------------------------------------------

VULNERABLE_APP = '''\
"""Tiny app with one planted flaw and one safe look-alike, for tests."""
import sqlite3

TABLE = "items"


def connect():
    conn = sqlite3.connect(":memory:")
    conn.execute(f"CREATE TABLE {TABLE} (name TEXT)")
    conn.execute("INSERT INTO items VALUES (?)", ("bolt",))
    return conn


def count(conn, name):
    sql = f"SELECT COUNT(*) FROM {TABLE} WHERE name = ?"
    return conn.execute(sql, (name,)).fetchone()[0]


def find(conn, name):
    return conn.execute(f"SELECT name FROM items WHERE name = '{name}'").fetchall()
'''

# Line 20 (`find`) is the real CWE-89. Line 15 (`count`) is the decoy: the table
# name is a module constant and the value is bound, but bandit's B608 flags it
# anyway -- which is exactly the false positive stage 2 has to clear.
VULN_LINE = 20
DECOY_LINE = 15

FIXED_APP = VULNERABLE_APP.replace(
    """    return conn.execute(f"SELECT name FROM items WHERE name = '{name}'").fetchall()""",
    '    return conn.execute("SELECT name FROM items WHERE name = ?", (name,)).fetchall()',
)

BROKEN_APP = VULNERABLE_APP.replace("def find(", "def find_renamed(")

SYNTAX_ERROR_APP = FIXED_APP + "\ndef oops(:\n"

CASE_CONFTEST = '''\
import importlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))


@pytest.fixture
def mod():
    return importlib.import_module(os.environ.get("TARGET_MODULE", "app"))
'''

CASE_FUNCTIONAL = '''\
def test_find_existing(mod):
    conn = mod.connect()
    assert mod.find(conn, "bolt") == [("bolt",)]


def test_find_missing(mod):
    conn = mod.connect()
    assert mod.find(conn, "nut") == []


def test_count(mod):
    conn = mod.connect()
    assert mod.count(conn, "bolt") == 1
'''

CASE_SECURITY = '''\
def test_v1_find_not_injectable(mod):
    conn = mod.connect()
    try:
        rows = mod.find(conn, "x' OR '1'='1")
    except Exception:
        rows = None
    assert not rows


def test_d1_count_is_safe(mod):
    conn = mod.connect()
    assert mod.count(conn, "x' OR '1'='1") == 0
    assert mod.count(conn, "bolt") == 1
'''


def make_case(tmp_path: Path,
              code: str = VULNERABLE_APP,
              case_id: str = "case_99_fake",
              with_functional: bool = True,
              with_security: bool = True) -> Case:
    """Write a dataset-shaped case folder under tmp_path and return the Case."""
    folder = tmp_path / case_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "app.py").write_text(code, encoding="utf-8")
    (folder / "conftest.py").write_text(CASE_CONFTEST, encoding="utf-8")
    if with_functional:
        (folder / "test_functional.py").write_text(CASE_FUNCTIONAL, encoding="utf-8")
    if with_security:
        (folder / "test_security.py").write_text(CASE_SECURITY, encoding="utf-8")
    return Case(
        case_id=case_id,
        path=folder,
        app_path=folder / "app.py",
        code=code,
        category="single",
        vulns=[Annotation(ann_id=f"{case_id}-v1", cwe="CWE-89",
                          line_start=VULN_LINE, line_end=VULN_LINE,
                          subtlety="obvious", expected_fix_risk="Low")],
        decoys=[Annotation(ann_id=f"{case_id}-d1", cwe="CWE-89",
                           line_start=DECOY_LINE, line_end=DECOY_LINE,
                           is_decoy=True)],
        has_functional_tests=with_functional,
        has_security_tests=with_security,
    )
