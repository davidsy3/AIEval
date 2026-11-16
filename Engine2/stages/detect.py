"""
STAGE 1 -- DETECT
=================

Job
---
Run Bandit over one case's `app.py`, add the AST rules for the shapes Bandit has
no rule for, map each hit to one of our five CWEs, and drop everything else.
This stage deliberately OVER-FLAGS: it sets the false-negative ceiling for the
whole pipeline. Anything it misses, no later stage can recover; anything it
over-reports, stage 2 can still throw away.

Three groups of rules run here:
  1. BANDIT, always. The baseline detector.
  2. CREDENTIAL AND CRYPTO RULES, always (`_credential_crypto_findings`). Each
     covers a position Bandit's name-based B105/B106/B324 cannot see: a literal
     secret that is returned, defaulted, nested in a dict, assigned to an
     attribute or named outside Bandit's wordlist; a credential recognisable
     from its own value (a published key format, or a URL carrying a password);
     a weak digest named in an argument or selected by string; a KDF with too
     few iterations; a fast digest over a password; a shell helper B605/B607
     does not list. None of them duplicates a Bandit hit.
  3. PATH TRAVERSAL, always (`_path_findings`). Bandit has no path-traversal
     rule of any kind. A path built from an argument that reaches a filesystem
     sink, or is returned from a helper, with no containment guard. The guard
     idioms it recognises are listed on `_is_guarded`.
  4. THE AST SUPPLEMENT, behind `--ast` (`_ast_findings`). Ported from v0. Now
     that group 3 covers CWE-22 on every run, this flag adds little but the
     CWE-89 and CWE-78 constructs Bandit already reported, roughly doubling the
     finding count for no detections. Kept because `--ast` is a documented CLI
     flag; worth retiring in a PR against run.py.

Contract
--------
    detect(case: Case, cfg=CONFIG) -> list[Finding]
    detect_code(code: str, case_id="", cfg=CONFIG) -> list[Finding]   # for a rescan
    detect_tree(root: Path, cfg=CONFIG) -> list[Finding]              # a whole project
    run_bandit(path: Path, cfg=CONFIG) -> list[dict]                  # raw bandit JSON

Owner: ____

Owns the number: FALSE-NEGATIVE RATE.

Known gaps (these show up directly in the numbers)
--------------------------------------------------
- SCOPE IS FIVE CWEs, SET IN config.py. `cfg.resolved_cwe()` drops everything
  else, so no rule here can report a sixth class without a reviewed PR against
  the shared `TARGET_CWES`. Worth knowing that the root README.md lists
  "vulnerable dependencies" as a supported class and omits CWE-327: nothing in
  either engine implements dependency scanning, and CWE-327 is 7 of the
  dataset's 34 vulns. One of the two documents is wrong.
- NO CROSS-FILE ANALYSIS. `detect_tree()` will walk a project, but every file is
  still judged alone: a sink in one module and the untrusted source that feeds it
  from another are never connected. Scanning a project is not understanding one,
  and following imports needs the taint analysis this stage does not have.
- TUNED ON 30 FILES. The dataset is stdlib-only, 40-150 lines, single-file.
  Several rules fire exactly once across it. Running the stage over v0's
  `Engine/testfile.py` is the cheapest reality check available; it is a
  Flask app with six planted credentials in shapes the dataset never uses.
- NO DATA FLOW ANYWHERE. Every rule here matches shapes in one file, with no
  idea where a value came from. `os.remove(os.path.join(dest, name))` is
  reported whether `name` arrived from a caller or from `listdir` of that same
  directory, and a hand-rolled validator called from the function being judged
  is invisible. This is the ceiling on what the stage can do without Semgrep
  taint rules, and it is where the remaining noise comes from.
- Bandit's import blacklist (B404 `import subprocess` as CWE-78, and friends)
  reports on the import line, which can never be a sink and can never fall
  within +/-3 lines of an annotation. Dropped here by `_on_an_import`, so the
  CWE-78 count no longer carries one guaranteed false positive per case that
  imports subprocess.
- One flaw spread over several functions is reported once per function. Findings
  are scored one-to-one against annotations, so the second report on the same
  flaw counts against us even though it is a correct observation.
- Bandit matches syntax, not data flow. The subtle dataset cases (a `shlex.quote`
  neutered by surrounding double quotes, a single-pass `../` strip, a prefix
  check with no separator) are missed or reported at the wrong line.
- `line_range` is used as-is; Bandit sometimes reports only the first line of a
  multi-line call, which narrows the window stage 5 matches on.
- `_dedupe` keys on an exact `(cwe, line_start)` match, so two detectors that
  describe one flaw on different lines -- Bandit on the query string, the AST
  supplement on the enclosing call -- both survive. Overlap-based merging would
  cut the raw count; stage 2's `_merge_groups` currently absorbs it instead.
- The credential rules read names, not data flow. A literal in a credential
  position is reported whether or not anything ever uses it, and a secret held
  in a name none of the patterns match is still missed.
- `MIN_PBKDF2_ITERATIONS` is a single global floor. It says nothing about the
  digest it is stretching, and there is no equivalent check for `scrypt` or
  `argon2` parameters.
- The fast-digest rule fires on the enclosing function's name or an argument
  name. A password passed in a variable called `value` or `raw`, or hashed in a
  helper called `_digest`, is missed.
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


def _import_lines(code: str) -> frozenset[int]:
    """Every line occupied by an import statement, or nothing if it won't parse.

    AST rather than a regex on the source: the word `import` inside a docstring
    or a string literal must not count, and these files are untrusted by design.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return frozenset()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            lines.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return frozenset(lines)


def _on_an_import(finding: Finding, import_lines: frozenset[int]) -> bool:
    """True when a finding's whole span is an import statement.

    An import is not a sink, so untrusted input cannot reach it and the finding
    cannot be a real instance of any of our five CWEs. It also cannot fall
    within +/-3 lines of an annotation, so it is a guaranteed false positive.

    This is Bandit's import blacklist: B404 reports `import subprocess` as
    CWE-78 on the import line, which was eight of this dataset's spurious
    findings. The same applies to the other blacklist rules (B403 pickle,
    B405/B406 XML) if the target CWEs ever widen, so the test is the line, not
    the rule id.

    Stage 2 has the same pre-filter as its own safety net. Dropping these here
    means it has nothing to do, which is the point: a finding stage 1 knows is
    wrong should not cost a judgement downstream.
    """
    return bool(import_lines) and finding.line_start in import_lines \
        and finding.line_end in import_lines


# Bandit's SQL rule. It matches a string that looks like SQL and is built at all,
# so it reports a parameterized query exactly as loudly as an injectable one.
_SQL_RULES = frozenset({"B608"})


def _interpolated(node) -> list | None:
    """The expressions a string-building node interpolates, or None if it is not one.

    `[]` means it builds a string out of constants only.
    """
    if isinstance(node, ast.JoinedStr):
        return [part.value for part in node.values
                if isinstance(part, ast.FormattedValue)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parts: list = []
        for side in (node.left, node.right):
            inner = _interpolated(side)
            if inner is not None:
                parts += inner
            elif not (isinstance(side, ast.Constant) and isinstance(side.value, str)):
                parts.append(side)
        return parts
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        right = node.right
        return list(right.elts) if isinstance(right, ast.Tuple) else [right]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return list(node.args) + [kw.value for kw in node.keywords]
        if node.func.attr == "join":
            return list(node.args)
    return None


def _constant_only_sql(code: str) -> tuple[frozenset[int], frozenset[int]]:
    """(lines building SQL from constants only, lines building it from a value).

    This is the distinction ../references/CWE-89.md draws:

        Interpolating a fixed identifier the program controls -- a table name
        from a module constant or an allowlist -- is not the same thing as
        interpolating a value.

    A query whose only interpolated part is a module constant, with user values
    passed as bound parameters, is not an instance of the weakness, and the
    dataset annotates several of exactly those as decoys.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return frozenset(), frozenset()
    bindings = _assign_bindings(tree)
    constant_only: set[int] = set()
    dynamic: set[int] = set()

    def span(node):
        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        return range(node.lineno, end + 1)

    def resolves_to_constant(node) -> bool:
        target = _resolve(node, bindings)
        return isinstance(target, ast.Constant)

    for node in ast.walk(tree):
        parts = _interpolated(node)
        if parts is None:
            # `cur.execute(query)` where `query` was built on an earlier line:
            # carry that line's verdict to this one.
            if isinstance(node, ast.Name):
                target = _resolve(node, bindings)
                if target is not node:
                    inner = _interpolated(target)
                    if inner is not None and not all(map(resolves_to_constant, inner)):
                        dynamic.update(span(node))
            continue
        (constant_only if all(map(resolves_to_constant, parts)) else dynamic) \
            .update(span(node))

    return frozenset(constant_only), frozenset(dynamic)


def _is_parameterized_sql(finding: Finding,
                          constant_only: frozenset[int],
                          dynamic: frozenset[int]) -> bool:
    """True when a SQL finding's query interpolates no untrusted value.

    Dropped: nothing on those lines builds a string at all (a fully static
    query, or one using bound parameters), or everything that does interpolates
    only constants. Kept whenever any line in the span is dynamic -- a mixed
    span fails safe toward reporting.
    """
    if finding.rule_id not in _SQL_RULES:
        return False
    lines = range(finding.line_start, finding.line_end + 1)
    if any(line in dynamic for line in lines):
        return False
    return True


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


# --- shared AST helpers ------------------------------------------------------
# Used by the optional supplement below and by the always-on credential/crypto
# rules after it.

# Names that put a string literal in a credential position. Deliberately broad:
# this stage over-flags, and stage 2 clears what it cannot justify. `salt` is
# NOT here on purpose -- cases 15 and 22 plant a hardcoded salt as part of their
# CWE-327 finding, and ground truth does not list it as CWE-798, so reporting it
# as a credential scores as a false positive (see ../dataset/README.md).
_SECRET_NAME = re.compile(
    r"(?:password|passwd|secret|token|api_?key|access_key|private_key|credential"
    r"|signing|(?:^|_)key$|(?:^|_)keys$|(?:^|_)pass$|(?:^|_)pwd$)", re.I)

# A value named like this is a password, so a bare digest over it is CWE-327
# however strong the digest is.
_PASSWORD_NAME = re.compile(r"(?:password|passwd|pwd|passphrase)", re.I)


def _alias_map(tree: ast.AST) -> dict[str, str]:
    """Imported name -> dotted original, so `from os import system` resolves."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _name_of(node, aliases: dict[str, str]) -> str:
    """Dotted name of a Name/Attribute node, with imports resolved; "" otherwise."""
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return f"{_name_of(node.value, aliases)}.{node.attr}"
    return ""


def _formatted(node) -> bool:
    """True for an f-string, a `+`/`%` concatenation, or a `.format()` call."""
    return (isinstance(node, ast.JoinedStr)
            or (isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)))
            or (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"))


def _assign_bindings(tree: ast.AST) -> dict[str, ast.AST]:
    """v0's resolve() step: `path = os.path.join(base, name)` then `open(path)`.

    Module-wide and last-wins, so it is imprecise across scopes -- see Known gaps.
    """
    bindings: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = node.value
    return bindings


def _resolve(node, bindings: dict[str, ast.AST], depth: int = 4):
    """Follow a Name through `bindings` to the expression it was last assigned."""
    seen: set[str] = set()
    while isinstance(node, ast.Name) and node.id in bindings and depth > 0:
        if node.id in seen:
            break
        seen.add(node.id)
        node = bindings[node.id]
        depth -= 1
    return node


def _enclosing_function(tree: ast.AST) -> dict[int, str]:
    """id(node) -> name of the function it sits in, innermost wins.

    `ast.walk` is breadth-first, so a nested function is visited after the one
    that contains it and overwrites its entries.
    """
    out: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                out[id(child)] = node.name
    return out


def _enclosing_funcdef(tree: ast.AST) -> dict[int, ast.AST]:
    """id(node) -> the FunctionDef it sits in, innermost wins.

    The node itself, not just the name: two classes can both define `_locate`,
    and per-function binding maps have to tell them apart.
    """
    out: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                out[id(child)] = node
    return out


def _literal_str(node) -> str | None:
    """The value of a non-empty string literal, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
        return node.value
    return None


def _keyword(node: ast.Call, name: str):
    """The value node of keyword argument `name`, or None."""
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _marked_not_for_security(node: ast.Call) -> bool:
    """True for `usedforsecurity=False`.

    The dataset has four decoys that hash with MD5 and say so explicitly -- an
    ETag, two cache keys and a storage shard. Honouring the flag is what keeps
    them out of the findings.
    """
    flag = _keyword(node, "usedforsecurity")
    return isinstance(flag, ast.Constant) and flag.value is False


# --- optional AST supplement (ported from v0 local_analyzer.py) --------------
# Off by default (`--ast`). It exists because Bandit has no CWE-22 rule; turning
# it on changes the false-negative ceiling, so report both numbers when you do.

def _ast_findings(code: str, case_id: str, cfg: Config) -> list[Finding]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    aliases = _alias_map(tree)
    bindings = _assign_bindings(tree)

    def name(node) -> str:
        return _name_of(node, aliases)

    def formatted(node) -> bool:
        return _formatted(node)

    def resolve(node, depth: int = 4):
        return _resolve(node, bindings, depth)

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
            if called in ("hashlib.md5", "hashlib.sha1") \
                    and not _marked_not_for_security(node):
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


# --- credential and crypto rules (always on) ---------------------------------
# These run on every scan, not behind `--ast`, because each one covers a shape
# Bandit has no rule for at all, and none of them re-flags something Bandit
# already reports. The `--ast` supplement above is a different trade: it exists
# for CWE-22 and pays for it by duplicating Bandit's CWE-89 and CWE-78 hits.
#
# What Bandit misses, and why:
#   B105/B106 match a literal against a wordlist of *assignment target* names,
#   so a literal that is returned, defaulted or nested in a dict is invisible.
#   B324 flags md5/sha1 by call name only, so a weak digest named in an argument
#   (`hmac.new(..., "md5")`), a fast digest used on a password, and a KDF run
#   with too few iterations are all invisible.

# PBKDF2 below this is treated as unstretched. 100k is the published floor
# (OWASP ASVS for PBKDF2-HMAC-SHA256); it is a floor, not a target. Keep it
# under the dataset's safe case, which stretches to 240k -- a threshold above
# that would report correct code.
MIN_PBKDF2_ITERATIONS = 100_000

# Digests that are broken outright. Weak wherever they carry a security meaning.
_BROKEN_DIGESTS = frozenset({"md5", "sha1", "md4", "sha"})

# A credential inside a connection string: `postgresql://admin:pw@host/db`.
# Carried over from v0's local_analyzer, which Engine2 dropped. The name of the
# variable tells you nothing here -- `DB_URL` matches no wordlist -- so the
# value is the only evidence.
_CREDENTIAL_URL = re.compile(r"://[^/\s:@]+:[^/\s@]+@")

# Published prefixes for real credential formats. Independent of the variable
# name and of any wordlist, which is what makes them worth having: a literal
# `AKIA...` is an AWS key wherever it appears and whatever it is called.
# Deliberately only formats that are documented and distinctive -- a generic
# entropy test would report every hash, UUID and base64 blob in the file.
_CREDENTIAL_LITERAL = re.compile(
    r"^(?:"
    r"AKIA[0-9A-Z]{12,}"                 # AWS access key id
    r"|ASIA[0-9A-Z]{12,}"                # AWS temporary access key id
    r"|A3T[0-9A-Z]{13,}"                 # AWS (older form)
    r"|sk_(?:live|test)_[0-9a-zA-Z]{16,}"  # Stripe secret key
    r"|rk_(?:live|test)_[0-9a-zA-Z]{16,}"  # Stripe restricted key
    r"|whsec_[0-9a-zA-Z]{16,}"           # Stripe webhook signing secret
    r"|sk-ant-[0-9A-Za-z_-]{16,}"        # Anthropic API key
    r"|sk-proj-[0-9A-Za-z_-]{16,}"       # OpenAI project key
    r"|gh[pousr]_[0-9A-Za-z]{16,}"       # GitHub token
    r"|github_pat_[0-9A-Za-z_]{16,}"     # GitHub fine-grained PAT
    r"|glpat-[0-9A-Za-z_-]{16,}"         # GitLab PAT
    r"|xox[baprs]-[0-9A-Za-z-]{10,}"     # Slack token
    r"|AIza[0-9A-Za-z_-]{30,}"           # Google API key
    r"|SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}"   # SendGrid
    r")$")

# Digests that are fine in general but far too fast to hash a password with.
_FAST_DIGESTS = frozenset({
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_256", "sha3_512", "blake2b", "blake2s",
})


def _digest_name(node, aliases: dict[str, str]) -> str:
    """Digest named by a node, as a bare lowercase word.

    Covers both ways a digest is passed: as a string (`"md5"`) and as a function
    (`hashlib.md5`, or a bare `md5` after `from hashlib import md5`).
    """
    literal = _literal_str(node)
    if literal:
        return literal.strip().lower().replace("-", "")
    return _name_of(node, aliases).rsplit(".", 1)[-1].lower()


def _credential_crypto_findings(code: str,
                                case_id: str,
                                cfg: Config) -> list[Finding]:
    """CWE-798 and CWE-327 in the positions Bandit's name-based rules cannot see."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    aliases = _alias_map(tree)
    bindings = _assign_bindings(tree)
    enclosing = _enclosing_function(tree)
    found: list[Finding] = []

    def add(node, cwe: str, rule_id: str, message: str) -> None:
        found.append(Finding(
            case_id=case_id, cwe=cwe,
            line_start=node.lineno, line_end=getattr(node, "end_lineno", node.lineno),
            detector="ast", rule_id=rule_id, severity="MEDIUM", confidence="MEDIUM",
            message=message,
        ))

    def mentions_password(node) -> bool:
        """True if any name inside this expression reads as a password."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and _PASSWORD_NAME.search(child.id):
                return True
            if isinstance(child, ast.Attribute) and _PASSWORD_NAME.search(child.attr):
                return True
        return False

    for node in ast.walk(tree):

        # --- CWE-798: the value is the evidence, wherever it sits ------------

        # A credential format or a connection string carrying a password. No
        # name and no position needed: `AKIA...` is an AWS key whatever it is
        # assigned to, and bandit's wordlist never sees either of these.
        literal = _literal_str(node)
        if literal and (_CREDENTIAL_URL.search(literal)
                        or _CREDENTIAL_LITERAL.match(literal.strip())):
            add(node, "CWE-798", "AST-798-literal",
                "String literal is a credential by its own format "
                "(API-key prefix, or a URL carrying a password).")

        # --- CWE-798: a literal secret in a credential-named position -------

        # `AWS_ACCESS_KEY_ID = "..."`, `app.secret_key = "..."`. B105 has this
        # shape but a narrower wordlist, and it does not look at attribute
        # targets, so both of those go unreported.
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if node.value is not None and _literal_str(node.value):
                for target in targets:
                    if _SECRET_NAME.search(_name_of(target, aliases)):
                        add(node, "CWE-798", "AST-798-assign",
                            f"{_name_of(target, aliases)} is assigned a "
                            "hard-coded string literal.")
                        break

        # `def _default_secret(): return "whsec_..."` -- B105 only looks at
        # assignment targets, so the function name is where the intent is.
        if isinstance(node, ast.Return) and node.value is not None:
            if _literal_str(node.value) \
                    and _SECRET_NAME.search(enclosing.get(id(node), "")):
                add(node, "CWE-798", "AST-798-return",
                    f"{enclosing[id(node)]}() returns a hard-coded string literal.")

        # `{"deploy_key": "dk_live_..."}` -- a credential keyed by name, which
        # no target-name rule can see.
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                key_name = _literal_str(key)
                if key_name and _literal_str(value) and _SECRET_NAME.search(key_name):
                    add(value, "CWE-798", "AST-798-dict",
                        f"dict entry {key_name!r} holds a hard-coded string literal.")

        if isinstance(node, ast.Call):
            called = _name_of(node.func, aliases)
            bare = called.rsplit(".", 1)[-1]

            # `os.environ.get("KEY", "literal")` -- the literal is the fallback,
            # so the program keeps working with the baked-in secret and nothing
            # fails closed. Name-independent: the position is the whole tell.
            # `os.environ["KEY"]` has no default and is correct, which is what
            # three of the dataset's CWE-798 decoys do.
            if called in ("os.environ.get", "os.getenv", "os.environ.setdefault") \
                    and len(node.args) >= 2 and _literal_str(node.args[1]):
                add(node, "CWE-798", "AST-798-envdefault",
                    "Environment lookup falls back to a hard-coded string literal.")

            # --- CWE-327: weak crypto Bandit's call-name rule cannot see ------

            # `hmac.new(key, msg, "md5")` -- the digest is an argument, so B324
            # never sees it. Third positional, or digestmod=.
            if called in ("hmac.new", "hmac.HMAC"):
                digestmod = (node.args[2] if len(node.args) >= 3
                             else _keyword(node, "digestmod"))
                if digestmod is not None \
                        and _digest_name(digestmod, aliases) in _BROKEN_DIGESTS:
                    add(node, "CWE-327", "AST-327-hmac",
                        f"HMAC built on {_digest_name(digestmod, aliases).upper()}.")

            # `hashlib.new("md5")` -- the digest is a string, so B324's
            # call-name matching misses it. v0's analyzer had this check and
            # Engine2 dropped it on the port.
            if called in ("hashlib.new", "hmac.digest") and node.args \
                    and not _marked_not_for_security(node):
                index = 2 if called == "hmac.digest" else 0
                if len(node.args) > index:
                    digest = _digest_name(node.args[index], aliases)
                    if digest in _BROKEN_DIGESTS:
                        add(node, "CWE-327", "AST-327-newdigest",
                            f"Weak digest {digest.upper()} selected by name.")

            # Helpers that always go through a shell. B605 and B607 cover
            # os.system and a partial list; these are the ones they miss.
            if called in ("subprocess.getoutput", "subprocess.getstatusoutput",
                          "os.popen2", "os.popen3", "os.popen4",
                          "commands.getoutput", "commands.getstatusoutput"):
                add(node, "CWE-78", "AST-78-shellhelper",
                    f"{called}() runs its argument through a shell.")

            # `pbkdf2_hmac("sha256", pw, salt, 1000)` -- the right primitive run
            # with too little work. Fourth positional, or iterations=.
            if bare == "pbkdf2_hmac":
                count = (node.args[3] if len(node.args) >= 4
                         else _keyword(node, "iterations"))
                resolved = _resolve(count, bindings) if count is not None else None
                if isinstance(resolved, ast.Constant) \
                        and isinstance(resolved.value, int) \
                        and not isinstance(resolved.value, bool) \
                        and resolved.value < MIN_PBKDF2_ITERATIONS:
                    add(node, "CWE-327", "AST-327-iterations",
                        f"PBKDF2 runs {resolved.value} iterations, "
                        f"under the {MIN_PBKDF2_ITERATIONS} floor.")

            # A fast digest over a password. SHA-256 is not a weak hash -- it is
            # the wrong tool here, because it is cheap enough to brute-force a
            # password list against. Bandit has no rule for "strong digest,
            # wrong job", so this is keyed on what is being hashed.
            if bare in _FAST_DIGESTS and not _marked_not_for_security(node):
                in_password_function = _PASSWORD_NAME.search(
                    enclosing.get(id(node), ""))
                if in_password_function or any(mentions_password(a)
                                               for a in node.args):
                    add(node, "CWE-327", "AST-327-fastdigest",
                        f"Password hashed with {bare.upper()}, "
                        "which needs no work factor to brute-force.")

    return [f for f in found if cfg.resolved_cwe(f.cwe)]


# --- path traversal (CWE-22, always on) --------------------------------------
# Bandit has no path-traversal rule at all, so this is the only CWE-22 coverage
# that does not depend on `--ast`.
#
# What makes a traversal finding different from the rules above: the dangerous
# construct and the safe one look identical. Every CWE-22 decoy in the dataset
# builds a path from an argument exactly as the vulnerable code does. What
# separates them is one idiom:
#
#     base = Path(base_dir).resolve()
#     target = (base / name).resolve()
#     if not target.is_relative_to(base):
#         raise ValueError(...)
#
# resolve() collapses the `..` steps, and the containment check rejects what
# escaped. All five decoys do this; none of the seven vulnerabilities does. A
# broken guard -- a single `../` strip, a `startswith` with no separator -- does
# not match, which is the point: those cases stay reported.
#
# The guard also has to carry to callers. In the clean cases a guarded helper
# returns the safe path and three or four other functions just use it, so a
# per-sink check with no propagation would report every one of them.

# `base / name`-style construction reaching one of these is the finding.
_PATH_SINK_FUNCS = frozenset({
    "open", "io.open", "os.remove", "os.unlink", "os.rmdir", "os.makedirs",
    "os.mkdir", "os.rename", "os.replace", "os.listdir", "os.stat", "os.chmod",
    "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree",
    "shutil.move", "shutil.rmtree", "shutil.unpack_archive",
    "shutil.make_archive", "tarfile.open", "zipfile.ZipFile",
})

# The pathlib equivalents, matched on the attribute name alone.
_PATH_SINK_METHODS = frozenset({
    "read_text", "read_bytes", "write_text", "write_bytes", "open",
    "unlink", "rmdir", "mkdir", "touch", "rename", "replace", "symlink_to",
})

# Containment checks that make a resolved path safe.
_PATH_GUARD_CHECKS = frozenset({"is_relative_to", "relative_to", "commonpath",
                                "commonprefix", "samefile"})

# Calls that normalise a path, which a real guard pairs with a check.
_PATH_NORMALISERS = frozenset({"resolve", "realpath"})

# Wrappers to look through: `Path(x)` and `x.resolve()` are not themselves
# construction, but what is inside them may be.
_PATH_WRAPPERS = frozenset({"Path", "PurePath", "PosixPath", "resolve",
                            "absolute", "expanduser", "abspath", "normpath"})


def _appends_untrusted_path(node, aliases: dict[str, str],
                            bindings: dict[str, ast.AST], depth: int = 4,
                            allow_concat: bool = False):
    """True when this expression APPENDS a non-constant part onto a path.

    Appending is the whole question. `Path(base_dir)` adopts a directory and is
    harmless; `base / name` and `os.path.join(base, name)` are where a `..`
    gets in. Checking the appended part specifically is what keeps
    `self.base / "uploads"` and `os.path.join(root, "staging")` out of the
    findings.

    `allow_concat` turns on plain string building (`f"{d}/{n}"`, `a + b`). Only
    the sink rule sets it: a concatenated string handed to `open()` is a path,
    but a bare concatenation on its own is usually not -- `md5(...) + SUFFIX`
    builds a cache filename, and treating that as path construction reported
    three of the dataset's decoys.
    """
    if depth <= 0 or node is None:
        return False
    node = _resolve(node, bindings)

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        if not isinstance(node.right, ast.Constant):
            return True
        return _appends_untrusted_path(node.left, aliases, bindings, depth - 1,
                                       allow_concat)

    if allow_concat and _formatted(node):
        return True

    if isinstance(node, ast.Call):
        called = _name_of(node.func, aliases)
        bare = called.rsplit(".", 1)[-1]
        if called == "os.path.join" or bare == "joinpath":
            # The first argument is the base; anything appended after it counts.
            if any(not isinstance(a, ast.Constant) for a in node.args[1:]):
                return True
            return _appends_untrusted_path(node.args[0], aliases, bindings,
                                           depth - 1, allow_concat) \
                if node.args else False
        if bare in _PATH_WRAPPERS:
            inner = (node.args[0] if node.args
                     else getattr(node.func, "value", None))
            return _appends_untrusted_path(inner, aliases, bindings, depth - 1,
                                           allow_concat)

    if isinstance(node, ast.Attribute) and node.attr in _PATH_WRAPPERS:
        return _appends_untrusted_path(node.value, aliases, bindings, depth - 1,
                                       allow_concat)

    return False


def _is_guarded(fn: ast.AST, aliases: dict[str, str]) -> bool:
    """True when `fn` defends against traversal in a way we recognise.

    Two idioms count:

    1. NORMALISE AND CONTAIN -- `resolve()` plus a containment check. Both
       halves are required: `os.path.abspath(p).startswith(base)`, case 12's
       planted flaw, normalises without really checking containment and so is
       not guarded, which is the verdict we want.
    2. REJECT ANYTHING THAT IS NOT A BARE FILENAME -- a comparison against
       `<path>.name`. If the candidate's final component has to equal the name
       that was asked for, no separator and no `..` can survive.

    Anything else -- a hand-rolled validator called from here, a name that came
    from `listdir` rather than from a caller -- is not visible to this stage.
    """
    normalises = checks = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare):
            for side in [node.left, *node.comparators]:
                if isinstance(side, ast.Attribute) and side.attr == "name":
                    return True
        if not isinstance(node, ast.Call):
            continue
        bare = _name_of(node.func, aliases).rsplit(".", 1)[-1]
        if bare in _PATH_NORMALISERS:
            normalises = True
        if bare in _PATH_GUARD_CHECKS:
            checks = True
    return normalises and checks


def _local_bindings(fn: ast.AST, module_bindings: dict[str, ast.AST]):
    """This function's own assignments, over the module's.

    Without this, `path` assigned in four different methods resolves to
    whichever came last in the file -- the module-wide gap the supplement has.
    """
    local = dict(module_bindings)
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    local[target.id] = node.value
    return local


def _path_findings(code: str, case_id: str, cfg: Config) -> list[Finding]:
    """CWE-22: a path built from an argument, with no containment guard."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    aliases = _alias_map(tree)
    module_bindings = _assign_bindings(tree)
    owner = _enclosing_funcdef(tree)
    functions = [n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    guarded = {fn.name for fn in functions if _is_guarded(fn, aliases)}

    # One finding per function: a function that builds a path and then uses it
    # twice has one flaw, and the dataset scores findings one-to-one against
    # annotations, so a second finding on the same flaw counts against us.
    found: dict[int, Finding] = {}

    def add(node, rule_id: str, message: str) -> None:
        fn = owner.get(id(node))
        key = id(fn) if fn is not None else id(node)
        if key in found:
            return
        found[key] = Finding(
            case_id=case_id, cwe="CWE-22",
            line_start=node.lineno, line_end=getattr(node, "end_lineno", node.lineno),
            detector="ast", rule_id=rule_id, severity="MEDIUM", confidence="MEDIUM",
            message=message,
        )

    def calls_guarded_helper(node) -> bool:
        """The path came back from a helper that already checked containment."""
        if not isinstance(node, ast.Call):
            return False
        return _name_of(node.func, aliases).rsplit(".", 1)[-1] in guarded

    # 1. Helpers that BUILD and return a path. This is where ground truth puts
    #    the vulnerability in five of the seven cases -- the flaw is the helper,
    #    not each of the three call sites that use it.
    builders: set[str] = set()
    for fn in functions:
        if _is_guarded(fn, aliases):
            continue
        bindings = _local_bindings(fn, module_bindings)
        for node in ast.walk(fn):
            if isinstance(node, ast.Return) and node.value is not None \
                    and not calls_guarded_helper(node.value) \
                    and _appends_untrusted_path(node.value, aliases, bindings):
                builders.add(fn.name)
                add(node, "AST-22-builder",
                    f"{fn.name}() returns a path built from its arguments with "
                    "no check that it stays inside the base directory.")
                break

    # 2. Sinks reached by a path built in the same function. Skipped when the
    #    path came from a guarded helper, or from a builder already reported --
    #    both are the same flaw counted twice.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = owner.get(id(node))
        if fn is not None and _is_guarded(fn, aliases):
            continue
        bindings = _local_bindings(fn, module_bindings) if fn is not None \
            else module_bindings

        called = _name_of(node.func, aliases)
        bare = called.rsplit(".", 1)[-1]
        if called in _PATH_SINK_FUNCS or bare in _PATH_SINK_FUNCS:
            target = node.args[0] if node.args else None
        elif bare in _PATH_SINK_METHODS and isinstance(node.func, ast.Attribute):
            target = node.func.value
        else:
            continue

        if target is None or calls_guarded_helper(target):
            continue
        resolved = _resolve(target, bindings)
        if calls_guarded_helper(resolved):
            continue
        if isinstance(resolved, ast.Call) and \
                _name_of(resolved.func, aliases).rsplit(".", 1)[-1] in builders:
            continue
        if _appends_untrusted_path(target, aliases, bindings, allow_concat=True):
            add(node, "AST-22-sink",
                f"{bare}() receives a path built from a variable part with no "
                "check that it stays inside the base directory.")

    return [f for f in found.values() if cfg.resolved_cwe(f.cwe)]


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
    import_lines = _import_lines(code)
    const_sql, dynamic_sql = _constant_only_sql(code)
    findings = [f for f in (_finding_from_bandit(r, case_id, cfg) for r in results)
                if f is not None and not _on_an_import(f, import_lines)
                and not _is_parameterized_sql(f, const_sql, dynamic_sql)]
    findings += _credential_crypto_findings(code, case_id, cfg)
    findings += _path_findings(code, case_id, cfg)
    if cfg.use_ast_supplement:
        findings += _ast_findings(code, case_id, cfg)
    return _dedupe(findings)


# Directories that are never source under review.
_SKIP_DIRS = frozenset({".venv", "venv", "__pycache__", ".git", ".pytest_cache",
                        "node_modules", "build", "dist", ".mypy_cache", ".tox",
                        "site-packages", ".eggs"})


def detect_tree(root: Path | str, cfg: Config = CONFIG) -> list[Finding]:
    """Every target-CWE finding in every .py file under `root`.

    The dataset is one file per case, but the VS Code extension's target is a
    project, so this is the entry point for scanning more than one file. Purely
    additive: `detect()` and its contract are untouched.

    `case_id` is each file's path relative to `root`, so a finding stays
    attributable once the results are pooled. Findings are ordered by path, then
    by the usual line/CWE order within a file.

    Known gaps
    ----------
    - One bandit subprocess per file. Fine for a file-at-a-time editor check,
      slow over a large tree; `bandit -r` on the whole directory in one call is
      the fix if that ever matters.
    - Still no cross-file analysis. Each file is judged alone, so a sink here
      and the untrusted source that feeds it from another module are not
      connected. Scanning a project is not the same as understanding one.
    - A file that will not decode as UTF-8 is skipped silently.
    """
    root = Path(root)
    paths = ([root] if root.is_file()
             else sorted(p for p in root.rglob("*.py")
                         if not _SKIP_DIRS & set(p.relative_to(root).parts)))
    findings: list[Finding] = []
    for path in paths:
        try:
            code = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        relative = path.name if path == root else str(path.relative_to(root))
        findings += detect_code(code, relative, cfg)
    return findings


def detect(case: Case, cfg: Config = CONFIG) -> list[Finding]:
    """Stage 1 entry point: every target-CWE finding in this case's app.py."""
    results = run_bandit(case.app_path, cfg)
    import_lines = _import_lines(case.code)
    const_sql, dynamic_sql = _constant_only_sql(case.code)
    findings = [f for f in (_finding_from_bandit(r, case.case_id, cfg) for r in results)
                if f is not None and not _on_an_import(f, import_lines)
                and not _is_parameterized_sql(f, const_sql, dynamic_sql)]
    findings += _credential_crypto_findings(case.code, case.case_id, cfg)
    findings += _path_findings(case.code, case.case_id, cfg)
    if cfg.use_ast_supplement:
        findings += _ast_findings(case.code, case.case_id, cfg)
    return _dedupe(findings)
