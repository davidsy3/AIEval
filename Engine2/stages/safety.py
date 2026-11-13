r"""
STAGE 4 -- SAFETY NET
=====================

!!!  THIS STAGE EXECUTES UNTRUSTED CODE                                 !!!
!!!                                                                    !!!
!!!  It runs pytest on (a) dataset code written to be vulnerable and    !!!
!!!  (b) code an LLM just generated. Each pytest run happens in a       !!!
!!!  Docker container (sandbox/Dockerfile, flags in _docker_command):   !!!
!!!  no network, only the case's *.py files mounted read-only, a        !!!
!!!  64 MB scratch /tmp, a non-root user, memory/CPU/process caps and   !!!
!!!  a 60 s kill. Nothing else from your machine is visible inside, and  !!!
!!!  nothing inside can write to your machine: the report comes back    !!!
!!!  over stdout, and the engine keeps only a capped tail of it.        !!!
!!!                                                                    !!!
!!!  Without Docker this stage REFUSES to run, unless you opt in with   !!!
!!!  --allow-unisolated / AIEVAL_ALLOW_UNISOLATED=1. Then the code runs !!!
!!!  as YOUR user, with YOUR files and YOUR network, and a case that    !!!
!!!  reads ~/.ssh or posts your files to a server simply succeeds.      !!!
!!!  Only opt in on dataset cases you have read.                        !!!

Job
---
Decide, WITHOUT ASKING A MODEL ANYTHING, whether a fix is good:

  0. reject, unrun, a fix that adds code no security fix needs (see
     FIX_MAY_IMPORT / FIX_MAY_NOT_ADD): `import atexit`, `os.fork`, `eval`...;
  1. copy the case's *.py files to a temp dir (oracles, conftest and all);
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
- The sandbox is a container, not a VM: it shares the host kernel. It also
  protects your machine, not the verdict: the code under test runs inside the
  pytest process that writes the report, so it can forge its own results. The
  added-code gate blocks the easy ways (an `atexit` hook, a forked or spawned
  helper, `eval`/`__import__`), and every leftover process is killed before the
  report is read, but a gate over source is not a proof. A fix whose ORIGINAL
  already used one of the blocked names may use it again.
- A run that produced no readable report counts as NOT RUN (never cached as a
  baseline), and a case with security tests whose security run produced no
  result counts as "vulnerability not gone". Both fail closed.
- Only *.py files are copied into the run (no symlinks, no hidden folders). A
  case that needs a data file (.csv, .json) will not find it.
- The container path is not exercised without Docker: the one real-container
  test is skipped on machines that have no Docker or no `aieval-sandbox` image.
- With --allow-unisolated there is NO ISOLATION (see the banner). Secret-looking
  environment variables are stripped, and nothing else.
- `vuln_gone` uses the security oracle (`test_v*`) when the case has one, and
  falls back to the re-scan only when it does not. A re-scan that crashes is
  NOT clear (fail closed). THE RE-SCAN FALLBACK IS WEAK:
  Bandit's B608 fires on a parameterized query too, so for CWE-89 it reports the
  SAME count on a vulnerable file and on a correct fix. `rescan_clear` is
  therefore ~never true for CWE-89, and a dataset without security tests would
  never auto-apply a SQL fix. Making the re-scan fix-aware is a first task.
- The re-scan is count-based per CWE, so a fix that silences a DECOY instead of
  the real flaw also scores as "clear", and removing two of three sites scores
  as "clear" with one left.
- The baseline runs once per case and is reused by later attempts (see
  _BASELINES). A stored baseline is reused only when the original code matches
  and `test_functional.py` still exists; it checks that the test file EXISTS,
  not what it says, so an edited test file under the same case_id and code
  reuses a stale baseline. A timed-out baseline is never stored.
- `test_v*` / `test_d*` prefixes come from `cfg`, but they are a dataset naming
  convention: a case set that names its tests differently silently yields
  `security_verdict = None` and falls back to the weak re-scan.
- pytest runs with the case's own conftest and TARGET_MODULE=app, which is the
  dataset's contract. A case that needs a different entry point will not run.
"""

from __future__ import annotations

import ast
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from config import CONFIG, Config
from models import Case, Finding, Fix, SafetyResult, TestRun
from stages.detect import detect_code


class SandboxUnavailable(RuntimeError):
    """Docker cannot run the tests and unisolated runs were not opted into."""


# Only these files are copied into a test run. An allowlist, not a blocklist:
# secrets live in .env, .env.local, credentials, id_rsa ... and names nobody
# predicted, and none of them end in .py. Symlinks are never followed (a link
# named app_data.py could point at ~/.ssh/id_rsa), hidden folders never copied.
ALLOWED_SUFFIXES = (".py",)
SKIPPED_DIRS = {"__pycache__", ".pytest_cache", ".venv", ".git"}


def _allowlist(directory: str, names: list[str]) -> set[str]:
    """shutil.copytree `ignore` callback: the names in `directory` NOT to copy."""
    ignored = set()
    for name in names:
        path = Path(directory) / name
        if path.is_symlink():
            ignored.add(name)
        elif path.is_dir():
            if name in SKIPPED_DIRS or name.startswith("."):
                ignored.add(name)
        elif not name.endswith(ALLOWED_SUFFIXES):
            ignored.add(name)
    return ignored

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


# The fix runs inside the pytest process that writes its own verdict, so a fix
# that registers an exit hook or leaves a helper process behind can rewrite the
# report and pass. Before running anything, compare the fix with the original:
#   - a NEW import must be one a security fix needs. This list is what the
#     dataset's 30 reference fixes add (os, hmac, pathlib, shlex, shutil,
#     subprocess) plus the stdlib modules the five CWE fixes call for.
#   - a NEW use of one of FIX_MAY_NOT_ADD, or of any dunder attribute
#     (`x.__dict__`, `f.__globals__`), is never part of a security fix.
# Anything the original already had is allowed again: the gate judges what the
# fix ADDS. An allowlist for imports, for the same reason as ALLOWED_SUFFIXES.
FIX_MAY_IMPORT = frozenset({
    "hashlib", "hmac", "os", "pathlib", "re", "secrets", "shlex", "shutil",
    "string", "subprocess",
})
FIX_MAY_NOT_ADD = frozenset({
    # code from strings, and reaching around the import allowlist
    "__import__", "__builtins__", "eval", "exec", "compile", "globals", "locals",
    "vars", "getattr", "setattr", "delattr", "breakpoint",
    # processes that outlive the test, or end it on the fix's terms
    "fork", "forkpty", "_exit", "abort", "kill", "killpg", "setsid", "Popen",
    "system", "popen", "posix_spawn", "posix_spawnp",
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp",
    "spawnvpe",
})


def _imports(tree: ast.AST) -> set[str]:
    """Top-level module names a tree imports; "." for any relative import."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            found.add("." if node.level else (node.module or "").split(".")[0])
    return found


def _risky_names(tree: ast.AST) -> set[str]:
    """Names, attributes and from-imported names in FIX_MAY_NOT_ADD, and dunder attributes."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names = [node.id]
        elif isinstance(node, ast.Attribute):
            names = [node.attr]
            if node.attr.startswith("__") and node.attr.endswith("__"):
                found.add(node.attr)        # `__file__` as a plain name stays allowed
        elif isinstance(node, ast.ImportFrom):
            names = [alias.name for alias in node.names]
        else:
            continue
        found |= {n for n in names if n in FIX_MAY_NOT_ADD}
    return found


def _added_code_problems(original: str, fixed: str) -> list[str]:
    """What the fix adds that no security fix needs. Empty when the fix may run."""
    try:
        before = ast.parse(original)
    except SyntaxError:
        before = ast.Module(body=[], type_ignores=[])   # judge the fix on its own
    after = ast.parse(fixed)                            # syntax checked by the caller
    imports = sorted(_imports(after) - _imports(before) - FIX_MAY_IMPORT)
    names = sorted(_risky_names(after) - _risky_names(before))
    return ([f"import {m}" if m != "." else "a relative import" for m in imports]
            + names)

# case_id -> (original code, completed baseline run). The baseline depends only
# on the original file, so attempts 2 and 3 reuse attempt 1's instead of running
# the same tests again. Lives as long as the process: one run.py run.
_BASELINES: dict[str, tuple[str, TestRun]] = {}


def _cached_baseline(case: Case) -> TestRun | None:
    """The stored baseline for this case, or None if it must be (re)run."""
    entry = _BASELINES.get(case.case_id)
    if entry is None or not (case.path / "test_functional.py").is_file():
        return None
    code, baseline = entry
    return baseline if code == case.code else None


BANNER = (
    "[stage 4] WARNING: Docker sandbox unavailable ({problem}). Running untrusted "
    "test code UNISOLATED because unisolated runs were opted into. See stages/safety.py."
)
_warned_unisolated = False

# image -> "" when Docker can run it, else what is wrong. Checked once per process.
_DOCKER_PROBLEM: dict[str, str] = {}


def _docker_problem(cfg: Config) -> str:
    """Empty string when the sandbox image is ready to run, else why it is not."""
    if cfg.sandbox_image not in _DOCKER_PROBLEM:
        try:
            proc = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", cfg.sandbox_image],
                capture_output=True, text=True, timeout=30,
            )
            problem = "" if proc.returncode == 0 else (
                f"`docker image inspect {cfg.sandbox_image}` failed: "
                f"{(proc.stderr or proc.stdout).strip()[-300:]}")
        except FileNotFoundError:
            problem = "Docker is not installed (no `docker` command on PATH)"
        except subprocess.TimeoutExpired:
            problem = "Docker did not answer within 30 s (is Docker Desktop running?)"
        _DOCKER_PROBLEM[cfg.sandbox_image] = problem
    return _DOCKER_PROBLEM[cfg.sandbox_image]


def sandbox_preflight(cfg: Config = CONFIG) -> str:
    """Check before any case runs. Returns "docker" or "UNISOLATED"; raises if neither is allowed."""
    problem = _docker_problem(cfg)
    if not problem:
        return "docker"
    if cfg.allow_unisolated:
        return "UNISOLATED"
    raise SandboxUnavailable(
        f"{problem}\n\n"
        "Stage 4 runs untrusted code and will not run it outside the sandbox.\n"
        "  - Install Docker Desktop and start it.\n"
        f"  - Build the image once, from engine2/:  docker build -t {cfg.sandbox_image} sandbox\n"
        "  - Or, ONLY on dataset cases you have read: --allow-unisolated\n"
        "    (or AIEVAL_ALLOW_UNISOLATED=1). The tests then run as you, unisolated.")


# Everything that comes back from a test run was written by the code under test,
# so the engine bounds it: OUTPUT_TAIL bytes of pytest output, a report of at
# most REPORT_MAX bytes, and never more than STREAM_MAX bytes held from a pipe
# however much the run prints.
OUTPUT_TAIL = 4000
REPORT_MAX = 1_000_000
STREAM_MAX = REPORT_MAX + OUTPUT_TAIL + 4096
REPORT_MARKER = "@@AIEVAL-JUNIT-REPORT@@"      # container stdout: output, marker, report


def _parse_report(xml: str | None) -> dict[str, bool] | None:
    """Per-test pass/fail from junit XML text; None when there is no usable report.

    Untrusted input: a DOCTYPE (entity tricks) is refused, and a malformed or
    truncated report is "no report", never an exception.
    """
    if not xml or not xml.strip() or "<!DOCTYPE" in xml.upper():
        return None
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    per_test: dict[str, bool] = {}
    for testcase in root.iter("testcase"):
        failed = any(child.tag in ("failure", "error") for child in testcase)
        skipped = any(child.tag == "skipped" for child in testcase)
        per_test[testcase.get("name", "?")] = not failed and not skipped
    return per_test


def _test_run(returncode: int, output: str, per_test: dict[str, bool] | None,
              isolated: bool) -> TestRun:
    """A finished (not timed-out) run.

    No readable report means the tests did not run to the end: Docker failed to
    start the container, pytest crashed, or the code under test ended the
    process early. That is ran=False -- never a pass, never a cached baseline.
    """
    if per_test is None:
        return TestRun(ran=False, returncode=returncode, isolated=isolated,
                       output=output or f"no test report (exit {returncode})")
    return TestRun(ran=True, passed=returncode == 0, returncode=returncode,
                   per_test=per_test, output=output, isolated=isolated)


def _run_capped(cmd: list[str], timeout: int, limit: int, on_timeout=None,
                **popen_args) -> tuple[int, str, bool]:
    """Run `cmd` -> (returncode, last `limit` bytes of stdout+stderr, timed_out).

    Holds at most `limit` bytes however much the process prints. `on_timeout`
    runs before the process is killed (the container path uses it to stop the
    container, which killing the `docker` client does not do).
    """
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, **popen_args)
    kept = bytearray()

    def drain() -> None:
        while chunk := proc.stdout.read1(65536):
            kept.extend(chunk)
            del kept[:-limit]

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timed_out = False
    try:
        returncode = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            if on_timeout:
                on_timeout()
        finally:
            proc.kill()
            returncode = proc.wait()
    reader.join(timeout=5)          # a leftover grandchild may hold the pipe open
    return returncode, bytes(kept).decode(errors="replace"), timed_out


def _run_pytest(workdir: Path, test_file: str, cfg: Config) -> TestRun:
    """Run one test file in `workdir` and record per-test pass/fail from junit XML."""
    global _warned_unisolated
    target = workdir / test_file
    if not target.is_file():
        return TestRun(ran=False, output=f"{test_file} not present")

    problem = _docker_problem(cfg)
    if not problem:
        return _run_in_container(workdir, test_file, cfg)
    if not cfg.allow_unisolated:
        sandbox_preflight(cfg)                      # raises SandboxUnavailable
    if not _warned_unisolated:
        print(BANNER.format(problem=problem), file=sys.stderr)
        _warned_unisolated = True
    return _run_unisolated(workdir, test_file, cfg)


_CONTAINER_REPORT = "/tmp/aieval-report.xml"
_CONTAINER_LOG = "/tmp/aieval-pytest.log"


def _container_script(test_file: str) -> str:
    """The shell line the container runs.

    pytest writes its output and report into the capped /tmp. When pytest exits,
    every other process is killed (`kill -9 -1` spares only the shell, PID 1),
    so nothing the fix left running can rewrite the report while it is read.
    Then stdout -- the only way out of the container -- carries the output tail,
    a marker line with pytest's exit code, and the report.
    """
    return (
        f"python -m pytest -q -p no:cacheprovider --junitxml={_CONTAINER_REPORT} "
        f"{shlex.quote(test_file)} >{_CONTAINER_LOG} 2>&1; rc=$?; "
        f"kill -9 -1 2>/dev/null; "
        f"tail -c {OUTPUT_TAIL} {_CONTAINER_LOG}; "
        f"printf '\\n%s %s\\n' {REPORT_MARKER} \"$rc\"; "
        f"head -c {REPORT_MAX} {_CONTAINER_REPORT} 2>/dev/null; "
        f"exit $rc"
    )


def _split_container_stream(stream: str) -> tuple[str, str | None]:
    """(pytest output, report XML or None) from the container's stdout.

    No marker means the shell never got past pytest: Docker failed to start the
    container (its error is the output), or the run was killed.
    """
    at = stream.rfind(f"\n{REPORT_MARKER} ")
    if at < 0:
        return stream[-OUTPUT_TAIL:], None
    line_end = stream.find("\n", at + 1)
    return stream[:at][-OUTPUT_TAIL:], (stream[line_end + 1:] if line_end >= 0 else "")


def _docker_command(name: str, workdir: Path, test_file: str, cfg: Config) -> list[str]:
    """The `docker run` line. Every flag here is one of stage 4's isolation rules."""
    return [
        "docker", "run", "--rm", "--name", name,
        "--network", "none",                                 # no network at all
        "--memory", cfg.sandbox_memory,
        "--memory-swap", cfg.sandbox_memory,                 # no swap on top
        "--cpus", cfg.sandbox_cpus,
        "--pids-limit", str(cfg.sandbox_pids),               # no fork bombs
        "--read-only",                                       # image files too
        "--tmpfs", f"/tmp:rw,size={cfg.sandbox_tmpfs_mb}m",  # the only scratch
        "--user", "1000:1000",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        # only what is passed here exists inside: no inherited variables at all
        "-e", "TARGET_MODULE=app",                           # the dataset's conftest contract
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-e", "HOME=/tmp",
        # The ONLY mount, read-only. Nothing in the container can write to the
        # host: the report comes back over stdout (see _container_script).
        "-v", f"{workdir}:/case:ro",
        "-w", "/case",
        cfg.sandbox_image,
        "sh", "-c", _container_script(test_file),
    ]


def _run_in_container(workdir: Path, test_file: str, cfg: Config) -> TestRun:
    name = f"aieval-{uuid.uuid4().hex[:12]}"

    kill_problem = ""

    def kill_container() -> None:
        # Killing the `docker` client does not stop the container; this does,
        # and with it every process inside. --rm then removes it.
        # If Docker itself does not answer, say so and carry on: the run is
        # already a timeout (a fail), and a stuck daemon must not turn it into
        # a crashed case. The container keeps its limits and has no network.
        nonlocal kill_problem
        try:
            subprocess.run(["docker", "kill", name], capture_output=True, timeout=30)
        except (subprocess.TimeoutExpired, OSError) as error:
            kill_problem = (f"[stage 4] could not stop container {name} after the "
                            f"timeout ({type(error).__name__}); it may still be "
                            f"running. Remove it with: docker rm -f {name}")
            print(kill_problem, file=sys.stderr)

    returncode, stream, timed_out = _run_capped(
        _docker_command(name, workdir, test_file, cfg), cfg.sandbox_timeout,
        STREAM_MAX, on_timeout=kill_container, env=_subprocess_env())
    output, report = _split_container_stream(stream)
    if timed_out:
        return TestRun(ran=True, passed=False, timed_out=True, returncode=-9,
                       output="\n".join(p for p in (output, kill_problem) if p),
                       isolated=True)
    return _test_run(returncode, output, _parse_report(report), isolated=True)


def _run_unisolated(workdir: Path, test_file: str, cfg: Config) -> TestRun:
    """Opt-in fallback: pytest as a plain subprocess, as YOU. See the banner."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.xml"
        env = _subprocess_env(
            TARGET_MODULE="app",           # the dataset's conftest contract
            PYTHONDONTWRITEBYTECODE="1",
        )
        returncode, output, timed_out = _run_capped(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             f"--junitxml={report}", test_file],
            cfg.test_timeout, OUTPUT_TAIL, cwd=workdir, env=env)
        if timed_out:
            return TestRun(ran=True, passed=False, timed_out=True, returncode=-9,
                           output=output)
        xml = (report.read_text(encoding="utf-8", errors="replace")
               if report.is_file() and not report.is_symlink()
               and report.stat().st_size <= REPORT_MAX else None)

    return _test_run(returncode, output, _parse_report(xml), isolated=False)


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
    if result.disallowed:
        parts.append("Your fix was NOT run. It adds code that removing these "
                     "vulnerabilities does not need: " + ", ".join(result.disallowed)
                     + ". Change only what the fix requires; new imports are limited "
                     "to " + ", ".join(sorted(FIX_MAY_IMPORT)) + ".")
    if result.applied and not result.functional_after.ran:
        parts.append("The functional tests produced no result on your fix: pytest "
                     "did not finish or wrote no report (did the module exit or "
                     "crash the process on import?).")
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
    security = result.security_after
    if security is not None and (not security.ran or security.timed_out):
        parts.append("The security tests produced no result on your fix (timed out, "
                     "crashed, or wrote no report), so the vulnerability cannot be "
                     "shown to be gone.")
    elif result.security_verdict is False:
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

    # 0. a fix that adds an exit hook, a helper process, eval ... is never run:
    #    running it is how it would forge its own verdict.
    result.disallowed = _added_code_problems(case.code, fix.fixed_code)
    if result.disallowed:
        result.feedback_for_repair = _feedback(result)
        return result

    with tempfile.TemporaryDirectory(prefix=f"aieval_{case.case_id}_") as tmp:
        workdir = Path(tmp) / case.path.name
        shutil.copytree(case.path, workdir, ignore=_allowlist)

        # 1. baseline on the ORIGINAL code: "passed before" is defined here.
        #    Run once per case; a run that did not complete is not kept, so the
        #    next attempt tries again.
        baseline = _cached_baseline(case)
        if baseline is None:
            (workdir / "app.py").write_text(case.code, encoding="utf-8")
            baseline = _run_pytest(workdir, "test_functional.py", cfg)
            if baseline.ran and not baseline.timed_out:
                _BASELINES[case.case_id] = (case.code, baseline)
        result.functional_baseline = baseline

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
    #    something broken). A case that ships security tests but got no result
    #    from them (no report, timed out) has NOT shown the flaw is gone: fail
    #    closed, rather than falling back to the weaker re-scan.
    security = result.security_after
    if case.has_security_tests and (security is None or not security.ran
                                    or security.timed_out):
        result.security_verdict = False
    elif security is not None and security.ran:
        per_test = security.per_test
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
    # did (or none). A re-scan that fails proves nothing, so it is NOT clear:
    # an empty finding list from a crashed scanner must not read as "all gone".
    rescan_error = ""
    try:
        rescan = detect_code(fix.fixed_code, case_id=case.case_id, cfg=cfg)
        before = detect_code(case.code, case_id=case.case_id, cfg=cfg)
    except Exception as error:                          # noqa: BLE001
        rescan, before = [], []
        rescan_error = f"{type(error).__name__}: {error}"
    result.rescan_findings = rescan
    addressed = set(fix.addressed_cwes) or {f.cwe for f in before}
    if rescan_error:
        result.rescan_clear = False
    else:
        result.rescan_clear = all(
            _count(rescan, cwe) < _count(before, cwe) or _count(rescan, cwe) == 0
            for cwe in addressed
        ) if addressed else not rescan

    # An executable oracle beats a pattern matcher: trust test_v* when the case
    # has one, and fall back to the re-scan when it does not. Both are recorded.
    result.vuln_gone = (result.security_verdict if result.security_verdict is not None
                        else result.rescan_clear)

    result.feedback_for_repair = _feedback(result)
    if rescan_error:
        result.feedback_for_repair = "\n\n".join(
            p for p in (result.feedback_for_repair, f"(re-scan failed: {rescan_error})") if p)
    return result
