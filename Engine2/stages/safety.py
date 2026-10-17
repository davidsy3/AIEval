r"""
STAGE 4 -- SAFETY NET
=====================

!!!  WARNING: THIS STAGE EXECUTES UNTRUSTED CODE WITH NO ISOLATION  !!!
!!!                                                                  !!!
!!!  It runs pytest, in a subprocess, on (a) dataset code written to !!!
!!!  be vulnerable and (b) code an LLM just generated. That code runs !!!
!!!  as YOUR user, with YOUR filesystem and YOUR network. The only   !!!
!!!  things between it and your machine are a temp directory, a       !!!
!!!  timeout, and a stripped environment (secret-looking variables    !!!
!!!  are removed -- see _subprocess_env). A case that calls           !!!
!!!  `rm -rf ~`, reads ~/.ssh, or posts your files to a server would  !!!
!!!  simply succeed. Removing env vars stops ONE leak, not the rest.  !!!
!!!                                                                  !!!
!!!  THIS OWNER'S FIRST JOB: move this execution into a container     !!!
!!!  with no network, a read-only mount of everything outside the     !!!
!!!  work dir, a non-root user, a memory/CPU cap and a hard kill      !!!
!!!  timeout. Until then, only run this stage on dataset cases you    !!!
!!!  have read, on a machine you are willing to lose.                 !!!

Job
---
Decide, WITHOUT ASKING A MODEL ANYTHING, whether a fix is good:

  1. copy the case folder to a temp dir (oracles, conftest and all);
  2. run `test_functional.py` against the ORIGINAL app.py  -> baseline;
  3. swap in the fixed code as app.py;
  4. run `test_functional.py` again                        -> after;
  5. optionally run `test_security.py`                     -> did the flaw go;
  6. re-scan the fixed code with stage 1                   -> is the CWE gone.

A regression is a test that PASSED in step 2 and FAILS in step 4. That is why
the baseline exists: a case whose tests were already failing is not a
regression, it is a broken case.

NEVER ask the model whether its own fix worked. The whole point of this stage is
that it is the one part of the pipeline a model cannot talk its way past.

Contract
--------
    verify(case: Case, fix: Fix, cfg=CONFIG) -> SafetyResult

Owner: ____

Owns the number: REGRESSION RATE.

Known gaps
----------
- NO ISOLATION (see the banner). This is the single biggest risk in the repo.
  Secret-looking environment variables are stripped from the test subprocess,
  which stops the API key leaking into code we run, and nothing else.
- `vuln_gone` uses the security oracle (`test_v*`) when the case has one, and
  falls back to the re-scan only when it does not. THE RE-SCAN FALLBACK IS WEAK:
  Bandit's B608 fires on a parameterized query too, so for CWE-89 it reports the
  SAME count on a vulnerable file and on a correct fix. `rescan_clear` is
  therefore ~never true for CWE-89, and a dataset without security tests would
  never auto-apply a SQL fix. Making the re-scan fix-aware is a first task.
- The re-scan is count-based per CWE, so a fix that silences a DECOY instead of
  the real flaw also scores as "clear", and removing two of three sites scores
  as "clear" with one left.
- The baseline is re-run on every attempt (3x per case worst case). It is a
  second or two, but it is waste.
- `test_v*` / `test_d*` prefixes come from `cfg`, but they are a dataset naming
  convention: a case set that names its tests differently silently yields
  `security_verdict = None` and falls back to the weak re-scan.
- pytest runs with the case's own conftest and TARGET_MODULE=app, which is the
  dataset's contract. A case that needs a different entry point will not run.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from config import CONFIG, Config
from models import Case, Finding, Fix, SafetyResult, TestRun
from stages.detect import detect_code

IGNORE = shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc", ".venv")

# Secret-looking variables are stripped before the environment is handed to the
# code we are about to run. ANTHROPIC_API_KEY is the one that matters here: the
# tests and the LLM-generated code we execute would otherwise be able to read
# it. The dataset's own CWE-798 tests monkeypatch os.environ through their
# `secret_env` / `empty_env` fixtures, so they do not need inherited secrets.
# This is a seatbelt, NOT isolation -- see the banner above.
_SECRET_ENV = re.compile(r"KEY|TOKEN|SECRET|PASS|CRED|AUTH", re.I)


def _subprocess_env(**overrides: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not _SECRET_ENV.search(k)}
    env.update(overrides)
    return env

BANNER = (
    "[stage 4] WARNING: running untrusted test code with no isolation "
    "(temp dir + timeout only). See stages/safety.py."
)


def _run_pytest(workdir: Path, test_file: str, cfg: Config) -> TestRun:
    """Run one test file in `workdir` and record per-test pass/fail from junit XML."""
    target = workdir / test_file
    if not target.is_file():
        return TestRun(ran=False, output=f"{test_file} not present")

    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.xml"
        env = _subprocess_env(
            TARGET_MODULE="app",           # the dataset's conftest contract
            PYTHONDONTWRITEBYTECODE="1",
        )
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                 f"--junitxml={report}", test_file],
                cwd=workdir, env=env, capture_output=True, text=True,
                timeout=cfg.test_timeout,
            )
        except subprocess.TimeoutExpired as expired:
            return TestRun(ran=True, passed=False, timed_out=True, returncode=-9,
                           output=(expired.stdout or b"").decode(errors="replace")[-4000:]
                           if isinstance(expired.stdout, bytes) else (expired.stdout or "")[-4000:])

        per_test: dict[str, bool] = {}
        if report.is_file():
            for testcase in ET.parse(report).getroot().iter("testcase"):
                failed = any(child.tag in ("failure", "error") for child in testcase)
                skipped = any(child.tag == "skipped" for child in testcase)
                per_test[testcase.get("name", "?")] = not failed and not skipped

    return TestRun(
        ran=True,
        passed=proc.returncode == 0,
        returncode=proc.returncode,
        per_test=per_test,
        output=(proc.stdout + proc.stderr)[-4000:],
    )


def _count(findings: list[Finding], cwe: str) -> int:
    return sum(1 for f in findings if f.cwe == cwe)


def _syntax_ok(code: str) -> tuple[bool, str]:
    try:
        compile(code, "app.py", "exec")
        return True, ""
    except SyntaxError as error:
        return False, f"{error.msg} at line {error.lineno}"


def _feedback(result: SafetyResult, syntax_error: str = "") -> str:
    """The text handed back to stage 3 for its next attempt. Facts only."""
    parts: list[str] = []
    if syntax_error:
        parts.append(f"Your fixed file does not parse: SyntaxError: {syntax_error}. "
                     f"Return the complete file, valid Python, nothing truncated.")
    if result.regressions:
        parts.append(
            "These functional tests PASSED on the original file and FAIL on your "
            "fix. Your fix changed observable behaviour:\n  - "
            + "\n  - ".join(result.regressions)
        )
    if result.functional_after.timed_out:
        parts.append("The functional tests timed out on your fix (possible infinite loop).")
    elif result.functional_after.ran and not result.functional_after.passed \
            and not result.regressions:
        parts.append("The functional tests fail on your fix (they also failed on the "
                     "original, so this is not strictly a regression).")
    if result.functional_after.output and (result.regressions
                                           or not result.functional_after.passed):
        parts.append("pytest output (truncated):\n" + result.functional_after.output[-2000:])
    if result.decoy_breaks:
        parts.append(
            "These tests cover code that was already SAFE and passed before your "
            "fix. Your fix broke them -- you rewrote code that did not need "
            "changing:\n  - " + "\n  - ".join(result.decoy_breaks))
    if result.security_verdict is False:
        parts.append("The security oracle still fails: the vulnerability is "
                     "still exploitable after your fix.")
    if not result.vuln_gone and result.rescan_findings:
        still = sorted({f"{f.cwe} line {f.line_start}" for f in result.rescan_findings})
        parts.append("The scanner still reports these on your fixed file: "
                     + ", ".join(still))
    return "\n\n".join(parts)


def verify(case: Case, fix: Fix, cfg: Config = CONFIG) -> SafetyResult:
    """Stage 4 entry point. Runs tests and a re-scan; asks no model anything."""
    result = SafetyResult(case_id=case.case_id, attempt=fix.attempt)

    if not fix.has_code:
        result.feedback_for_repair = "There was no fixed code to test."
        return result

    ok, syntax_error = _syntax_ok(fix.fixed_code or "")
    result.syntax_ok = ok
    if not ok:
        result.feedback_for_repair = _feedback(result, syntax_error)
        return result

    print(BANNER, file=sys.stderr)

    with tempfile.TemporaryDirectory(prefix=f"aieval_{case.case_id}_") as tmp:
        workdir = Path(tmp) / case.path.name
        shutil.copytree(case.path, workdir, ignore=IGNORE)

        # 1. baseline on the ORIGINAL code: "passed before" is defined here.
        (workdir / "app.py").write_text(case.code, encoding="utf-8")
        result.functional_baseline = _run_pytest(workdir, "test_functional.py", cfg)

        # 2. swap in the fix and re-run the same tests.
        (workdir / "app.py").write_text(fix.fixed_code, encoding="utf-8")
        result.applied = True
        result.functional_after = _run_pytest(workdir, "test_functional.py", cfg)

        # 3. security oracle, if the case ships one.
        if case.has_security_tests:
            result.security_after = _run_pytest(workdir, "test_security.py", cfg)

    # 4. regressions: passed before, fails after.
    before = result.functional_baseline.passing_names
    after = result.functional_after.passing_names
    result.regressions = sorted(before - after)

    # 5. the security oracle's two halves: test_v* must now pass (the planted flaw
    #    is really gone), test_d* must still pass (safe code was not rewritten into
    #    something broken).
    if result.security_after is not None and result.security_after.ran:
        per_test = result.security_after.per_test
        vuln_tests = {n: ok for n, ok in per_test.items()
                      if n.startswith(cfg.vuln_test_prefix)}
        result.security_verdict = all(vuln_tests.values()) if vuln_tests else None
        result.decoy_breaks = sorted(n for n, ok in per_test.items()
                                     if n.startswith(cfg.decoy_test_prefix) and not ok)

    # 6. re-scan with stage 1 and ask whether the addressed CWEs are gone.
    #
    # Compared against a scan of the ORIGINAL file, per CWE, by count. Stage 1
    # over-flags on purpose, so "the re-scan reports no CWE-89 at all" is a test
    # almost no correct fix can pass: the decoy lines keep firing. A CWE counts
    # as gone when the fixed file reports strictly fewer of it than the original
    # did (or none).
    try:
        rescan = detect_code(fix.fixed_code, case_id=case.case_id, cfg=cfg)
        before = detect_code(case.code, case_id=case.case_id, cfg=cfg)
    except Exception as error:                          # noqa: BLE001
        rescan, before = [], []
        result.feedback_for_repair = f"(re-scan failed: {error})"
    result.rescan_findings = rescan
    addressed = set(fix.addressed_cwes) or {f.cwe for f in before}
    result.rescan_clear = all(
        _count(rescan, cwe) < _count(before, cwe) or _count(rescan, cwe) == 0
        for cwe in addressed
    ) if addressed else not rescan

    # An executable oracle beats a pattern matcher: trust test_v* when the case
    # has one, and fall back to the re-scan when it does not. Both are recorded.
    result.vuln_gone = (result.security_verdict if result.security_verdict is not None
                        else result.rescan_clear)

    result.feedback_for_repair = _feedback(result)
    return result
