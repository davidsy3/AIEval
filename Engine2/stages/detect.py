"""
STAGE 1 -- DETECT
=================

Job
---
Run Bandit over one case's `app.py`, map each hit to one of our five CWEs, and
drop everything else. This stage deliberately OVER-FLAGS: it sets the
false-negative ceiling for the whole pipeline. Anything it misses, no later
stage can recover; anything it over-reports, stage 2 can still throw away.

Contract
--------
    detect(case: Case, cfg=CONFIG) -> list[Finding]
    detect_code(code: str, case_id="", cfg=CONFIG) -> list[Finding]   # for a rescan
    run_bandit(path: Path, cfg=CONFIG) -> list[dict]                  # raw bandit JSON

Owner: ____

Owns the number: FALSE-NEGATIVE RATE.

Known gaps (these show up directly in the numbers)
--------------------------------------------------
- BANDIT HAS NO PATH-TRAVERSAL RULE. All CWE-22 vulnerabilities in the dataset
  are invisible to this stage, so the CWE-22 false-negative rate is ~100%.
  First task: add a CWE-22 check (the v0 AST checks in `_ast_findings` below are
  a starting point; Semgrep rules are the planned real answer).
- B404 flags `import subprocess` itself as CWE-78, on the import line. That can
  never fall within +/-3 lines of a real annotation, so it is a guaranteed false
  positive on every case that imports subprocess.
- Bandit matches syntax, not data flow. The subtle dataset cases (a `shlex.quote`
  neutered by surrounding double quotes, a single-pass `../` strip, a prefix
  check with no separator) are missed or reported at the wrong line.
- `line_range` is used as-is; Bandit sometimes reports only the first line of a
  multi-line call, which narrows the window stage 5 matches on.
- The AST supplement resolves assignments module-wide and last-wins, so a name
  rebound in two functions resolves to whichever assignment came last in the
  file. It also reports the `open()` line, not the line where the path was
  built, which is often where ground truth puts the vulnerability.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from config import CONFIG, Config
from models import Case, Finding


# --- bandit ------------------------------------------------------------------

def run_bandit(path: Path | str, cfg: Config = CONFIG) -> list[dict]:
    """Run bandit on one file and return its raw `results` list.

    Bandit exits 1 when it finds something, so the return code is not an error
    signal here; only a missing/failed run is.
    """
    path = Path(path)
    proc = subprocess.run(
        [sys.executable, "-m", "bandit", "-f", "json", "-q", str(path)],
        capture_output=True, text=True, timeout=cfg.bandit_timeout,
    )
    if not proc.stdout.strip():
        raise RuntimeError(
            f"bandit produced no JSON for {path} (exit {proc.returncode}): "
            f"{proc.stderr.strip()[:400]}"
        )
    return json.loads(proc.stdout).get("results", [])


def _cwe_of(result: dict) -> str | None:
    """Bandit >=1.7.3 reports `issue_cwe: {"id": 89, ...}`; older builds do not."""
    raw = result.get("issue_cwe") or {}
    if isinstance(raw, dict) and raw.get("id") is not None:
        return f"CWE-{raw['id']}"
    match = re.search(r"CWE-(\d+)", json.dumps(raw) if raw else "")
    return match.group(0) if match else None


def _finding_from_bandit(result: dict, case_id: str, cfg: Config) -> Finding | None:
    cwe = cfg.resolved_cwe(_cwe_of(result))
    if cwe is None:
        return None
    line_range = result.get("line_range") or [result.get("line_number", 1)]
    return Finding(
        case_id=case_id,
        cwe=cwe,
        line_start=min(line_range),
        line_end=max(line_range),
        detector="bandit",
        rule_id=result.get("test_id", ""),
        severity=result.get("issue_severity", ""),
        confidence=result.get("issue_confidence", ""),
        message=result.get("issue_text", "").strip(),
        snippet=(result.get("code") or "").strip(),
    )


# --- optional AST supplement (ported from v0 local_analyzer.py) --------------
# Off by default (`--ast`). It exists because Bandit has no CWE-22 rule; turning
# it on changes the false-negative ceiling, so report both numbers when you do.

_SECRET_NAME = re.compile(
    r"(?:password|passwd|secret|token|api_?key|access_key|(?:^|_)pass$)", re.I)


def _ast_findings(code: str, case_id: str, cfg: Config) -> list[Finding]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def name(node) -> str:
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{name(node.value)}.{node.attr}"
        return ""

    def formatted(node) -> bool:
        return (isinstance(node, ast.JoinedStr)
                or (isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)))
                or (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "format"))

    # v0's resolve() step: `path = os.path.join(base, name)` then `open(path)`.
    # Module-wide and last-wins, so it is imprecise across scopes -- see Known gaps.
    bindings: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = node.value

    def resolve(node, depth: int = 4):
        seen: set[str] = set()
        while isinstance(node, ast.Name) and node.id in bindings and depth > 0:
            if node.id in seen:
                break
            seen.add(node.id)
            node = bindings[node.id]
            depth -= 1
        return node

    found: list[Finding] = []

    def add(node, cwe: str, message: str) -> None:
        found.append(Finding(
            case_id=case_id, cwe=cwe,
            line_start=node.lineno, line_end=getattr(node, "end_lineno", node.lineno),
            detector="ast", rule_id="AST", severity="MEDIUM", confidence="MEDIUM",
            message=message,
        ))

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
                for target in targets:
                    if _SECRET_NAME.search(name(target)):
                        add(node, "CWE-798",
                            f"{name(target)} is assigned a string literal that looks like a secret.")
        if isinstance(node, ast.Call):
            called = name(node.func)
            first = resolve(node.args[0]) if node.args else None
            if called.endswith((".execute", ".executemany", ".executescript")) and formatted(first):
                add(node, "CWE-89", "Query passed to execute() is built by string formatting.")
            shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                        and k.value.value is True for k in node.keywords)
            if called in ("os.system", "os.popen") or (shell and called.startswith("subprocess.")):
                add(node, "CWE-78", "Command is run through a shell.")
            if called in ("hashlib.md5", "hashlib.sha1"):
                add(node, "CWE-327", "Weak hash (MD5/SHA-1).")
            # The CWE-22 check Bandit does not have: a variable path reaching open().
            if called in ("open", "io.open") and first is not None:
                joined = (isinstance(first, ast.Call)
                          and name(first.func) in ("os.path.join", "Path", "pathlib.Path")
                          and any(not isinstance(a, ast.Constant) for a in first.args))
                attr_path = (isinstance(first, ast.Call)
                             and isinstance(first.func, ast.Attribute)
                             and first.func.attr in ("joinpath", "resolve", "absolute"))
                concat = formatted(first)
                binop_path = (isinstance(first, ast.BinOp) and isinstance(first.op, ast.Div))
                if joined or concat or binop_path or attr_path:
                    add(node, "CWE-22", "File opened with a path built from variable parts.")

    return [f for f in found if cfg.resolved_cwe(f.cwe)]


# --- the stage ---------------------------------------------------------------

def _dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per (cwe, line_start); bandit wins over the AST supplement."""
    best: dict[tuple[str, int], Finding] = {}
    for f in sorted(findings, key=lambda f: (f.detector != "bandit", f.line_start)):
        best.setdefault((f.cwe, f.line_start), f)
    return sorted(best.values(), key=lambda f: (f.line_start, f.cwe))


def detect_code(code: str, case_id: str = "", cfg: Config = CONFIG) -> list[Finding]:
    """Scan a code string. Used for the stage-4 rescan of a fixed file."""
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "app.py"
        target.write_text(code, encoding="utf-8")
        results = run_bandit(target, cfg)
    findings = [f for f in (_finding_from_bandit(r, case_id, cfg) for r in results)
                if f is not None]
    if cfg.use_ast_supplement:
        findings += _ast_findings(code, case_id, cfg)
    return _dedupe(findings)


def detect(case: Case, cfg: Config = CONFIG) -> list[Finding]:
    """Stage 1 entry point: every target-CWE finding in this case's app.py."""
    results = run_bandit(case.app_path, cfg)
    findings = [f for f in (_finding_from_bandit(r, case.case_id, cfg) for r in results)
                if f is not None]
    if cfg.use_ast_supplement:
        findings += _ast_findings(case.code, case.case_id, cfg)
    return _dedupe(findings)
