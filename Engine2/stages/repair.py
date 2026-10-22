"""
STAGE 3 -- REPAIR  (LLM)
========================

Job
---
Rewrite the WHOLE file so the confirmed vulnerabilities are gone and the
program still behaves exactly as before. Report a compatibility risk
(Low/Medium/High) that stage 5 uses to decide whether a human must look.

The prompt, the target-CWE list and the A-E report format are carried over from
the v0 engine (`Engine/fixer.py`), including the untrusted-input rules. Keeping
the A-E format means v0 reports and v1 reports parse with the same code.

Two rules that must not be changed without a PR:
  - There is a "NO FIX POSSIBLE" escape hatch. A model that cannot fix
    something without changing behaviour must say so instead of guessing.
  - Repair accepts `feedback` from a failed previous attempt (stage 4's
    `feedback_for_repair`) and must be given it on every retry.

Contract
--------
    repair(case, confirmed, llm, cfg=CONFIG, feedback=None, attempt=1) -> Fix

Owner: ____

Owns the number: shares REGRESSION RATE with stage 4 (stage 3 causes
regressions, stage 4 catches them).

Known gaps
----------
- Whole-file rewrite. The model reformats or "improves" untouched code, which
  makes diffs noisy and is the main source of regressions. A patch-level repair
  (edit only the vulnerable lines) is the obvious first task.
- `risk` is the model's own self-assessment, and it is optimistic: it tends to
  say Low. Nothing calibrates it against what stage 4 actually observes.
- The feedback loop passes failures as text. It does not single out which
  failing test maps to which change.
- No token-budget check: a file close to `max_tokens` can return truncated code,
  which stage 4 then rejects on a syntax error (correct, but wasteful).
"""

from __future__ import annotations

import re

from config import CONFIG, Config
from llm import INJECTION_RULES, LLM, wrap_untrusted
from models import Case, Fix, TriagedFinding

# Carried over from v0 fixer.py.
TARGET_VULNERABILITIES = """\
- CWE-89  SQL Injection            (untrusted input concatenated into a query)
- CWE-78  OS Command Injection     (untrusted input passed to a shell / exec call)
- CWE-22  Path Traversal           (untrusted input used to build a file path)
- CWE-798 Hard-coded Credentials   (passwords, API keys, secrets in source code)
- CWE-327 Broken / Weak Cryptography (MD5, SHA-1, DES, ECB mode, etc.)
"""

SYSTEM_PROMPT = f"""\
You are a senior application security engineer. You are given a complete source
file and a list of CONFIRMED vulnerabilities in it, already triaged by a human-
grade review. Your job is to fix exactly those, focusing ONLY on these classes:

{TARGET_VULNERABILITIES}

Rules for the fix:
  - Produce a corrected version of the FULL file. It must be a drop-in
    replacement for the original: same module-level names, same function
    signatures, same return shapes, same exceptions for the same inputs.
  - Do NOT introduce new dependencies or call APIs not already available in the
    Python standard library.
  - Do NOT change behaviour, structure, or formatting beyond what the fix needs.
  - Prefer standard, idiomatic fixes: parameterized queries, argument lists
    instead of shell strings, path canonicalization checked against an allowed
    base directory, secrets read from environment variables (and FAILING CLOSED
    when the variable is missing -- never fall back to a default or empty
    secret), strong password hashing with a per-value random salt and a
    stretching KDF at 100k+ iterations.
  - Existing callers and stored data must keep working. If old records were
    written with a weak scheme, keep verifying them while storing new values
    with the strong one.

ESCAPE HATCHES -- use these instead of guessing:
  - If you cannot fix a confirmed vulnerability without risking a change in
    behaviour, do NOT rewrite it. Write "NO FIX POSSIBLE" in section D, and
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
```python
<the complete corrected file, or NO FIX POSSIBLE>
```

E. PROPOSE TO HUMAN
<anything you chose NOT to fix, and why, or "NONE">
"""

NO_FIX = "NO FIX POSSIBLE"


# --- A-E parsing (same shape as v0 fixer.py) ---------------------------------

def extract_section(report: str, name: str, next_name: str | None) -> str:
    if next_name:
        pattern = rf"{re.escape(name)}\s*(.*?)(?:\n\s*{re.escape(next_name)}|\Z)"
    else:
        pattern = rf"{re.escape(name)}\s*(.*)"
    match = re.search(pattern, report or "", re.DOTALL)
    return match.group(1).strip() if match else ""


def extract_fixed_code(report: str) -> str | None:
    """Section D's code block, or None when there is nothing to apply."""
    section = extract_section(report, "D. FIXED CODE", "E. PROPOSE TO HUMAN")
    if not section or NO_FIX in section.upper() or "NO CHANGES" in section.upper():
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


# --- the stage ---------------------------------------------------------------

def repair(case: Case,
           confirmed: list[TriagedFinding],
           llm: LLM,
           cfg: Config = CONFIG,
           feedback: str | None = None,
           attempt: int = 1) -> Fix:
    """Stage 3 entry point. One whole-file rewrite attempt."""
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

    try:
        report = llm.complete(
            SYSTEM_PROMPT + INJECTION_RULES,
            build_user_message(case, confirmed, feedback, attempt),
        )
    except Exception as error:                          # noqa: BLE001
        return Fix(case_id=case.case_id, attempt=attempt, fixed_code=None,
                   risk="High", addressed_cwes=cwes,
                   notes=f"repair call failed ({type(error).__name__}: {error})")

    code = extract_fixed_code(report)
    section_d = extract_section(report, "D. FIXED CODE", "E. PROPOSE TO HUMAN")
    return Fix(
        case_id=case.case_id,
        attempt=attempt,
        fixed_code=code,
        risk=extract_risk(report),
        no_fix_possible=NO_FIX in section_d.upper() or NO_FIX in report.upper(),
        addressed_cwes=cwes,
        notes="" if code else "no fixed code in section D",
        raw_llm=report,
    )
