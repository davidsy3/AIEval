"""
STAGE 3 -- REPAIR  (LLM)
========================

Job
---
Remove the confirmed vulnerabilities while keeping the program's behaviour
exactly as before, and report a compatibility risk (Low/Medium/High) that
stage 5 uses to decide whether a human must look.

The model returns PATCH-LEVEL edits: SEARCH/REPLACE blocks that quote lines of
the original file and give their replacement. This stage applies them to the
original file itself, so every line the model did not quote stays byte-for-byte
the same. Whole-file rewriting, where the model reformats or "improves" code it
was never asked to touch, was the main source of regressions. A complete file in
section D (the v0 shape) is still accepted as a fallback.

The prompt, the target-CWE list and the A-E report format are carried over from
the v0 engine (`Engine/fixer.py`), including the untrusted-input rules. Keeping
the A-E format means v0 reports and v1 reports parse with the same code; only
the contents of section D changed (edit blocks instead of a whole file).

Two rules that must not be changed without a PR:
  - There is a "NO FIX POSSIBLE" escape hatch. A model that cannot fix
    something without changing behaviour must say so instead of guessing.
  - Repair accepts `feedback` from a failed previous attempt (stage 4's
    `feedback_for_repair`) and must be given it on every retry.

How one call to `repair()` works
--------------------------------
  1. ask for an A-E report whose section D holds SEARCH/REPLACE edits;
  2. apply the edits to `case.code`. Each SEARCH must match exactly one place
     (trailing whitespace is tolerated, nothing else is);
  3. if an edit does not apply, ask ONCE more with the exact apply error. This
     is a formatting retry inside one attempt, not one of the orchestrator's
     behaviour retries, which need stage 4's feedback;
  4. set a RISK FLOOR by inspecting the change (see `assess_risk`). The final
     risk is the higher of the model's rating and the floor: the model may say
     High when we would say Low, but never the other way round.

Contract
--------
    repair(case, confirmed, llm, cfg=CONFIG, feedback=None, attempt=1) -> Fix

Owner: ____

Owns the number: shares REGRESSION RATE with stage 4 (stage 3 causes
regressions, stage 4 catches them).

Known gaps
----------
- The risk floor is structural, not semantic. It catches a removed or renamed
  name, an incompatible signature, a new third-party import and edits outside
  the flagged code. It cannot see a changed return value or exception inside a
  function the model was allowed to edit. Calibrating `risk` against what
  stage 4 observes is still open.
- "Outside the flagged code" means outside the top-level statements that
  contain a confirmed finding, their one-hop name dependencies (callers of a
  fixed helper, readers of a removed secret) and the imports. Dependencies are
  found by NAME, not by resolving them: two unrelated functions that share a
  method name count as related. A correct fix that also has to change a
  function two hops away is floored at Medium, so a human sees it. Deliberate:
  over-review is the safe direction.
- The feedback loop passes failures as text. It does not single out which
  failing test maps to which edit, and the previous attempt's edits are not
  shown again (the contract only carries `feedback`).
- No token-budget check before the call. Patch output is small, so truncation
  is now unlikely; a truncated reply is detected and reported in `notes`, but
  the attempt is still spent.
"""

from __future__ import annotations

import ast
import difflib
import re
import sys
from dataclasses import dataclass

from config import CONFIG, Config
from llm import INJECTION_RULES, LLM, wrap_untrusted
from models import Case, Fix, Risk, TriagedFinding

# Carried over from v0 fixer.py.
TARGET_VULNERABILITIES = """\
- CWE-89  SQL Injection            (untrusted input concatenated into a query)
- CWE-78  OS Command Injection     (untrusted input passed to a shell / exec call)
- CWE-22  Path Traversal           (untrusted input used to build a file path)
- CWE-798 Hard-coded Credentials   (passwords, API keys, secrets in source code)
- CWE-327 Broken / Weak Cryptography (MD5, SHA-1, DES, ECB mode, etc.)
"""

SEARCH_MARK = "<<<<<<< SEARCH"
DIVIDER_MARK = "======="
REPLACE_MARK = ">>>>>>> REPLACE"

SYSTEM_PROMPT = f"""\
You are a senior application security engineer. You are given a complete source
file and a list of CONFIRMED vulnerabilities in it, already triaged by a human-
grade review. Your job is to fix exactly those, focusing ONLY on these classes:

{TARGET_VULNERABILITIES}

Rules for the fix:
  - The fixed file must be a drop-in replacement for the original: same
    module-level names, same function signatures, same return shapes, same
    exceptions for the same inputs.
  - Do NOT introduce new dependencies or call APIs not already available in the
    Python standard library.
  - Do NOT change behaviour, structure, or formatting beyond what the fix needs.
    Lines you do not need to change must not appear in your edits at all.
  - Prefer standard, idiomatic fixes: parameterized queries, argument lists
    instead of shell strings, path canonicalization checked against an allowed
    base directory, secrets read from environment variables (and FAILING CLOSED
    when the variable is missing -- never fall back to a default or empty
    secret), strong password hashing with a per-value random salt and a
    stretching KDF at 100k+ iterations.
  - Existing callers and stored data must keep working. If old records were
    written with a weak scheme, keep verifying them while storing new values
    with the strong one.

How to write the fix -- EDIT BLOCKS, not a whole file:
  Section D is a list of edit blocks. Each block is exactly:

{SEARCH_MARK}
<one or more COMPLETE lines copied verbatim from the original file>
{DIVIDER_MARK}
<the lines that replace them>
{REPLACE_MARK}

  - SEARCH lines must be copied character for character from the file,
    including indentation. Never include line numbers.
  - Each SEARCH must match exactly ONE place in the file. Include a few
    neighbouring lines if a line appears more than once, but keep blocks short.
  - Blocks are applied top to bottom and must not overlap.
  - To ADD lines (an import, a helper), SEARCH for an existing anchor line and
    repeat that anchor in the replacement together with the new lines.
  - To DELETE lines, leave the replacement empty.

ESCAPE HATCHES -- use these instead of guessing:
  - If you cannot fix a confirmed vulnerability without risking a change in
    behaviour, do NOT edit it. Write "NO FIX POSSIBLE" in section D, and
    explain in section E what a developer has to decide.
  - If, having read the whole file, you believe a confirmed finding is not
    actually a vulnerability, leave that code alone and say so in section E.

Respond in EXACTLY this format, with these headers:

A. FINDINGS
<the confirmed vulnerabilities you addressed, with CWE id and line>

B. EXPLANATIONS
<for each: what you changed and why that removes the flaw>

C. COMPATIBILITY RISK
<Low | Medium | High -- how likely your fix changes observable behaviour, and why.
 Low = safe to auto-apply. Medium/High = must be reviewed by a human first.>

D. FIXED CODE
<the edit blocks, or NO FIX POSSIBLE>

E. PROPOSE TO HUMAN
<anything you chose NOT to fix, and why, or "NONE">
"""

NO_FIX = "NO FIX POSSIBLE"

# One extra call when the model's edits do not apply. Formatting problems only:
# a behaviour retry needs stage 4's feedback and belongs to the orchestrator.
PATCH_RETRIES = 1

_RISK_ORDER: dict[str, int] = {"Low": 0, "Medium": 1, "High": 2}


# --- A-E parsing (same shape as v0 fixer.py) ---------------------------------

def extract_section(report: str, name: str, next_name: str | None) -> str:
    if next_name:
        pattern = rf"{re.escape(name)}\s*(.*?)(?:\n\s*{re.escape(next_name)}|\Z)"
    else:
        pattern = rf"{re.escape(name)}\s*(.*)"
    match = re.search(pattern, report or "", re.DOTALL)
    return match.group(1).strip() if match else ""


def _section_d(report: str) -> str:
    return extract_section(report, "D. FIXED CODE", "E. PROPOSE TO HUMAN")


def _says_no_fix(section: str) -> bool:
    upper = section.upper()
    return NO_FIX in upper or "NO CHANGES" in upper


def extract_fixed_code(report: str) -> str | None:
    """Section D as a WHOLE FILE (the v0 shape), or None when there is none.

    Returns None for an edit-block section D: edit blocks are never a file, and
    must go through `extract_edits` + `apply_edits` instead.
    """
    section = _section_d(report)
    if not section or _says_no_fix(section) or SEARCH_MARK in section:
        return None
    block = re.search(r"```[^\n]*\n(.*?)\n\s*```", section, re.DOTALL)
    if block:
        return block.group(1) + "\n"
    # Some replies drop the fence; accept the raw section if it parses as code.
    return section + "\n" if section.lstrip().startswith(("import", "from", '"""', "#")) else None


def extract_risk(report: str) -> str:
    section = extract_section(report, "C. COMPATIBILITY RISK", "D. FIXED CODE")
    match = re.search(r"\b(Low|Medium|High)\b", section, re.I)
    return match.group(1).capitalize() if match else "High"


# --- patch-level edits -------------------------------------------------------

class PatchError(ValueError):
    """An edit block could not be applied. The message is shown to the model."""


_EDIT_BLOCK = re.compile(
    r"^[ \t]*<{5,9}[ \t]*SEARCH[^\n]*\n"     # <<<<<<< SEARCH
    r"(.*?)"                                 # search lines (may be empty -> rejected)
    r"^[ \t]*={5,9}[ \t]*\n"                 # =======
    r"(.*?)"                                 # replacement lines (may be empty)
    r"^[ \t]*>{5,9}[ \t]*REPLACE[^\n]*$",    # >>>>>>> REPLACE
    re.DOTALL | re.MULTILINE,
)


def extract_edits(report: str) -> list[tuple[str, str]]:
    """The (search, replace) pairs in section D, in order. Empty if there are none."""
    section = _section_d(report)
    if not section or SEARCH_MARK not in section:
        return []
    # Search inside the raw section so fenced and unfenced blocks both parse.
    return [(m.group(1), m.group(2)) for m in _EDIT_BLOCK.finditer(section + "\n")]


def _find_window(lines: list[str], needle: list[str], loose: bool) -> list[int]:
    """Start indexes where `needle` matches `lines` line for line."""
    norm = (lambda s: s.rstrip()) if loose else (lambda s: s)
    target = [norm(s) for s in needle]
    width = len(target)
    return [i for i in range(len(lines) - width + 1)
            if [norm(s) for s in lines[i:i + width]] == target]


def _preview(lines: list[str], limit: int = 3) -> str:
    shown = "\n".join(f"      {line}" for line in lines[:limit])
    return shown + ("\n      ..." if len(lines) > limit else "")


def apply_edits(original: str, edits: list[tuple[str, str]]) -> str:
    """Apply SEARCH/REPLACE edits to `original`, line-wise, in order.

    Matching is on WHOLE lines, so a SEARCH can never match half a line. An
    exact match is tried first, then one that ignores trailing whitespace.
    Anything else -- no match, or more than one -- raises PatchError, because
    guessing which place the model meant is how a fix lands on the wrong line.
    """
    if not edits:
        raise PatchError("section D contains no edit blocks")
    lines = original.splitlines()
    for number, (search, replace) in enumerate(edits, 1):
        needle, new = search.splitlines(), replace.splitlines()
        # Leading/trailing blank lines in SEARCH are usually spacing, not intent.
        # Trim them, and trim as many from the same end of the replacement, so
        # blank context quoted on both sides is neither lost nor doubled.
        while needle and not needle[0].strip():
            needle.pop(0)
            if new and not new[0].strip():
                new.pop(0)
        while needle and not needle[-1].strip():
            needle.pop()
            if new and not new[-1].strip():
                new.pop()
        if not needle:
            raise PatchError(f"edit {number}: the SEARCH part is empty. Quote at least "
                             f"one existing line as an anchor.")
        hits = _find_window(lines, needle, loose=False) or \
            _find_window(lines, needle, loose=True)
        if not hits:
            raise PatchError(
                f"edit {number}: these SEARCH lines do not appear in the file "
                f"(copy them verbatim, with indentation and no line numbers):\n"
                + _preview(needle))
        if len(hits) > 1:
            raise PatchError(
                f"edit {number}: these SEARCH lines match {len(hits)} places "
                f"(lines {', '.join(str(h + 1) for h in hits)}); add neighbouring "
                f"lines so they match exactly one:\n" + _preview(needle))
        start = hits[0]
        lines[start:start + len(needle)] = new
    return "\n".join(lines) + ("\n" if original.endswith("\n") or not original else "")


def _looks_truncated(report: str) -> bool:
    """A reply cut off by max_tokens: an unclosed fence or edit block in section D."""
    section = _section_d(report)
    if section.count("```") % 2:
        return True
    return section.count(SEARCH_MARK) > section.count(REPLACE_MARK)


# --- risk floor --------------------------------------------------------------

@dataclass
class _Symbol:
    kind: str                     # def | async def | class | name
    args: ast.arguments | None = None


def _interface(tree: ast.Module) -> dict[str, _Symbol]:
    """Module-level names a caller can depend on, and class methods as `Cls.m`."""
    out: dict[str, _Symbol] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            out[node.name] = _Symbol(kind, node.args)
        elif isinstance(node, ast.ClassDef):
            out[node.name] = _Symbol("class")
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    kind = "async def" if isinstance(item, ast.AsyncFunctionDef) else "def"
                    out[f"{node.name}.{item.name}"] = _Symbol(kind, item.args)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name):
                        out.setdefault(name.id, _Symbol("name"))
    return out


def _shape(args: ast.arguments) -> dict:
    positional = [a.arg for a in args.posonlyargs + args.args]
    n_defaults = len(args.defaults)
    return {
        "positional": positional,
        "required": len(positional) - n_defaults,
        "defaults": [ast.unparse(d) for d in args.defaults],
        "kwonly": {a.arg: (ast.unparse(d) if d is not None else None)
                   for a, d in zip(args.kwonlyargs, args.kw_defaults)},
        "vararg": args.vararg is not None,
        "kwarg": args.kwarg is not None,
    }


def _signature_change(old: ast.arguments, new: ast.arguments) -> str | None:
    """None if identical; 'compatible' if every old call still works; else 'breaking'."""
    a, b = _shape(old), _shape(new)
    if a == b:
        return None
    breaking = (
        b["positional"][:len(a["positional"])] != a["positional"]
        or b["required"] > a["required"]
        or any(k not in b["kwonly"] for k in a["kwonly"])
        or any(v is None for k, v in b["kwonly"].items()
               if k not in a["kwonly"] or a["kwonly"][k] is not None)
        or (a["vararg"] and not b["vararg"])
        or (a["kwarg"] and not b["kwarg"])
    )
    return "breaking" if breaking else "compatible"


def _top_level_modules(tree: ast.Module) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods.add(node.module.split(".")[0])
    return mods


def _node_span(node: ast.stmt) -> tuple[int, int]:
    start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
    return start, node.end_lineno or node.lineno


def _node_label(node: ast.stmt) -> str:
    name = getattr(node, "name", None)
    return f"`{name}`" if name else f"the statement at line {node.lineno}"


def _defines(node: ast.stmt) -> set[str]:
    """Names a top-level statement binds (function, class, or assigned names)."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names = {node.name}
        if isinstance(node, ast.ClassDef):
            names |= {item.name for item in node.body
                      if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
        return names
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)}
    return set()


def _uses(node: ast.stmt) -> set[str]:
    """Names a top-level statement reads or calls (`f(...)`, `X`, `self.m(...)`)."""
    used: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
            used.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            used.add(sub.attr)
    return used


def _out_of_scope_edits(original: str, fixed: str, tree: ast.Module,
                        confirmed: list[TriagedFinding], tolerance: int) -> list[str]:
    """Labels of top-level statements the fix edited that are unrelated to any finding.

    In scope:
      - every top-level statement overlapping a confirmed finding's lines;
      - ONE HOP of dependency from those: a statement that uses a name the
        flagged code defines (the caller of a fixed helper, the function that
        reads a hard-coded secret) or defines a name the flagged code uses;
      - every import, and new lines inserted BETWEEN top-level statements (a
        new helper or import).
    Blank-line-only changes are ignored.
    """
    nodes = [(node, *_node_span(node)) for node in tree.body]
    flagged: set[int] = set()
    loose_lines: set[int] = set()
    for t in confirmed:
        f_start, f_end = t.finding.line_start, t.finding.line_end
        hit = False
        for index, (node, start, end) in enumerate(nodes):
            if start <= f_end and f_start <= end:
                flagged.add(index)
                hit = True
        if not hit:     # a finding on a comment or blank line: allow its neighbourhood
            loose_lines.update(range(f_start - tolerance, f_end + tolerance + 1))

    defined = set().union(*(_defines(nodes[i][0]) for i in flagged)) if flagged else set()
    used = set().union(*(_uses(nodes[i][0]) for i in flagged)) if flagged else set()
    allowed = set(flagged)
    for index, (node, _, _) in enumerate(nodes):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            allowed.add(index)
        elif _uses(node) & defined or _defines(node) & used:
            allowed.add(index)

    def containing(line: int) -> int | None:
        for index, (_, start, end) in enumerate(nodes):
            if start <= line <= end:
                return index
        return None

    old_lines, new_lines = original.splitlines(), fixed.splitlines()
    outside: list[int] = []
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if not any(s.strip() for s in old_lines[i1:i2] + new_lines[j1:j2]):
            continue                                    # whitespace-only change
        if tag == "insert":
            # New lines between original lines i1 and i1+1 (1-based): out of scope
            # only when that gap is strictly inside a disallowed statement.
            for index, (_, start, end) in enumerate(nodes):
                if start <= i1 < end and index not in allowed and i1 not in loose_lines:
                    outside.append(index)
            continue
        for line in range(i1 + 1, i2 + 1):
            index = containing(line)
            if index is not None and index not in allowed and line not in loose_lines:
                outside.append(index)

    seen: list[str] = []
    for index in outside:
        label = _node_label(nodes[index][0])
        if label not in seen:
            seen.append(label)
    return seen


def assess_risk(original: str,
                fixed: str,
                confirmed: list[TriagedFinding],
                cfg: Config = CONFIG) -> tuple[Risk, list[str]]:
    """The LOWEST risk this change can honestly carry, and the reasons for it.

    Looks only at the code, never at the model's opinion. Stage 4 still decides
    whether the fix works; this decides whether it may skip a human.
    """
    reasons: list[tuple[Risk, str]] = []
    try:
        new_tree = ast.parse(fixed)
    except SyntaxError as error:
        return "High", [f"fixed file does not parse ({error.msg} at line {error.lineno})"]
    try:
        old_tree = ast.parse(original)
    except SyntaxError:
        return "High", ["original file does not parse, so the change cannot be checked"]

    if fixed == original:
        return "High", ["the fix changes nothing"]

    # Public names are what callers import. A private helper's shape is the
    # module's own business: its only callers are in this file, the fix has to
    # update them, and stage 4's tests run them. So private signature changes
    # set no floor; edits to unrelated callers are caught by the scope check.
    old_api, new_api = _interface(old_tree), _interface(new_tree)
    for name, old in old_api.items():
        new = new_api.get(name)
        public = not name.split(".")[-1].startswith("_")
        if new is None:
            if public and old.kind != "name":
                reasons.append(("High", f"removed `{name}`"))
            elif public:
                # Usually the CWE-798 fix itself (a hard-coded secret constant
                # removed), but code importing that name breaks: a human looks.
                reasons.append(("Medium", f"removed module-level name `{name}`"))
        elif new.kind != old.kind:
            reasons.append(("High" if public else "Medium",
                            f"`{name}` changed from {old.kind} to {new.kind}"))
        elif public and old.args is not None and new.args is not None:
            change = _signature_change(old.args, new.args)
            if change == "breaking":
                reasons.append(("High", f"incompatible signature change in `{name}`"))
            elif change == "compatible":
                reasons.append(("Medium", f"signature of `{name}` changed "
                                          f"(old calls still work)"))

    stdlib = set(getattr(sys, "stdlib_module_names", ()))
    added = _top_level_modules(new_tree) - _top_level_modules(old_tree)
    third_party = sorted(m for m in added if m not in stdlib and m != "__future__")
    if third_party:
        reasons.append(("High", "new non-stdlib import: " + ", ".join(third_party)))

    outside = _out_of_scope_edits(original, fixed, old_tree, confirmed, cfg.line_tolerance)
    if outside:
        reasons.append(("Medium", "edited code with no confirmed finding: "
                                  + ", ".join(outside)))

    floor: Risk = "Low"
    for risk, _ in reasons:
        if _RISK_ORDER[risk] > _RISK_ORDER[floor]:
            floor = risk
    return floor, [text for _, text in reasons]


def _max_risk(a: str, b: str) -> Risk:
    return a if _RISK_ORDER.get(a, 2) >= _RISK_ORDER.get(b, 2) else b   # type: ignore[return-value]


# --- prompt assembly ---------------------------------------------------------

def _confirmed_block(confirmed: list[TriagedFinding]) -> str:
    lines = []
    for index, t in enumerate(confirmed, 1):
        f = t.finding
        lines.append(
            f"{index}. {f.cwe} at lines {f.line_start}-{f.line_end} "
            f"({f.detector} {f.rule_id})\n"
            f"   what: {t.explanation.what or f.message}\n"
            f"   why:  {t.explanation.why}\n"
            f"   how:  {t.explanation.how_exploited}"
        )
    return "\n".join(lines) or "(none)"


def build_user_message(case: Case,
                       confirmed: list[TriagedFinding],
                       feedback: str | None = None,
                       attempt: int = 1) -> str:
    parts = [f"CONFIRMED VULNERABILITIES TO FIX\n{_confirmed_block(confirmed)}"]
    if feedback:
        parts.append(
            f"THIS IS ATTEMPT {attempt}. YOUR PREVIOUS FIX WAS REJECTED BY AN\n"
            f"AUTOMATED SAFETY NET (tests and a re-scan, not an opinion):\n\n"
            f"{feedback}\n\n"
            "Fix the same vulnerabilities again, and make the above not happen. "
            "Treat the test output as ground truth about behaviour."
        )
    parts.append(wrap_untrusted(case.code, path=f"{case.case_id}/app.py"))
    return "\n\n".join(parts)


def _patch_failure_note(error: PatchError) -> str:
    return (
        "YOUR PREVIOUS REPLY COULD NOT BE APPLIED. Its edit blocks did not match "
        "the file:\n\n"
        f"{error}\n\n"
        "Reply again with the complete A-E report. Copy every SEARCH line exactly "
        "from the file between the markers above."
    )


# --- the stage ---------------------------------------------------------------

def _code_from_report(report: str, original: str) -> tuple[str | None, str]:
    """(fixed code or None, note). Edit blocks first; a whole file is the fallback.

    Raises PatchError when section D has edit blocks that do not apply.
    """
    section = _section_d(report)
    if _says_no_fix(section):
        return None, ""
    edits = extract_edits(report)
    if edits:
        return apply_edits(original, edits), f"patch: {len(edits)} edit(s) applied"
    if SEARCH_MARK in section:
        raise PatchError("section D has a SEARCH marker but no complete edit block "
                         f"(each needs {SEARCH_MARK}, {DIVIDER_MARK} and {REPLACE_MARK})")
    code = extract_fixed_code(report)
    if code:
        return code, "whole-file reply (no edit blocks); used as the fixed file"
    if _looks_truncated(report):
        return None, "reply looks truncated (unclosed block in section D)"
    return None, "no fixed code in section D"


def repair(case: Case,
           confirmed: list[TriagedFinding],
           llm: LLM,
           cfg: Config = CONFIG,
           feedback: str | None = None,
           attempt: int = 1) -> Fix:
    """Stage 3 entry point. One repair attempt, as patch-level edits."""
    cwes = sorted({t.finding.cwe for t in confirmed})

    # OFFLINE: return the code unchanged at High risk, so nothing auto-applies
    # but stages 4 and 5 still have something real to run.
    if llm.offline:
        return Fix(
            case_id=case.case_id, attempt=attempt, fixed_code=case.code,
            risk="High", addressed_cwes=cwes,
            notes="offline: code returned unchanged, risk forced to High",
        )

    if not confirmed:
        return Fix(case_id=case.case_id, attempt=attempt, fixed_code=None,
                   risk="Low", notes="nothing confirmed to repair")

    system = SYSTEM_PROMPT + INJECTION_RULES
    user = build_user_message(case, confirmed, feedback, attempt)
    reports: list[str] = []
    notes: list[str] = []
    code: str | None = None
    patch_failed = False

    for ask in range(PATCH_RETRIES + 1):
        try:
            report = llm.complete(system, user)
        except Exception as error:                      # noqa: BLE001
            notes.append(f"repair call failed ({type(error).__name__}: {error})")
            return Fix(case_id=case.case_id, attempt=attempt, fixed_code=None,
                       risk="High", addressed_cwes=cwes, notes="; ".join(notes),
                       raw_llm=_join_reports(reports))
        reports.append(report)
        try:
            code, note = _code_from_report(report, case.code)
            if note:
                notes.append(note)
            patch_failed = False
            break
        except PatchError as error:
            notes.append(f"edits did not apply ({error})".replace("\n", " "))
            code = None
            patch_failed = True
            if ask < PATCH_RETRIES:
                user = (build_user_message(case, confirmed, feedback, attempt)
                        + "\n\n" + _patch_failure_note(error))

    final = reports[-1]
    section_d = _section_d(final)
    model_risk = extract_risk(final)
    risk: Risk = "High" if patch_failed else model_risk  # type: ignore[assignment]
    if code is not None:
        floor, reasons = assess_risk(case.code, code, confirmed, cfg)
        risk = _max_risk(model_risk, floor)
        if reasons:
            notes.append(f"risk floor {floor} (model said {model_risk}): "
                         + "; ".join(reasons))

    return Fix(
        case_id=case.case_id,
        attempt=attempt,
        fixed_code=code,
        risk=risk,
        no_fix_possible=NO_FIX in section_d.upper() or NO_FIX in final.upper(),
        addressed_cwes=cwes,
        notes="; ".join(notes),
        raw_llm=_join_reports(reports),
    )


def _join_reports(reports: list[str]) -> str:
    return "\n\n----- re-asked: previous edits did not apply -----\n\n".join(reports)
