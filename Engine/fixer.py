"""
AI Code Vulnerability Fixer -- v0
=================================
The simplest possible version: ONE LLM call with detailed instructions.

It takes a source file, asks Claude to find and fix a fixed, stated set of
vulnerability classes, and prints the triage, explanations, a compatibility-risk
rating, and the fixed code.

No static analyzer, no RAG, no dataset -- those come later. All the "smarts"
live in SYSTEM_PROMPT below, which is the only part you should be tuning for now.

Setup
-----
    cd engine
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env          # then paste your key into .env
                                  # get one at console.anthropic.com

Run
---
    python fixer.py testfile.py
"""

import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import anthropic
from dotenv import load_dotenv

# Load ANTHROPIC_API_KEY from engine/.env regardless of where the script is run from.
load_dotenv(Path(__file__).resolve().parent / ".env")

# Fixed files and reports are written here; the input file is never modified.
OUTPUT_DIR = Path(__file__).resolve().parent / "output"

# --- Your capstone's "defined and stated class list" (v0 subset) ---------------
# These 5 are the CWEs LLMs are documented to repair *well*. Broken access control
# is deliberately left out of v0 -- it's where repair fails and regression risk is
# highest, so it becomes a "propose to a human" case in a later version.
TARGET_VULNERABILITIES = """\
- CWE-89  SQL Injection            (untrusted input concatenated into a query)
- CWE-78  OS Command Injection     (untrusted input passed to a shell / exec call)
- CWE-22  Path Traversal           (untrusted input used to build a file path)
- CWE-798 Hard-coded Credentials   (passwords, API keys, secrets in source code)
- CWE-327 Broken / Weak Cryptography (MD5, SHA-1, DES, ECB mode, etc.)
"""

# --- The heart of the system: detailed directions for the model ----------------
SYSTEM_PROMPT = f"""\
You are a senior application security engineer. You are given a complete source
file and must find and fix security vulnerabilities in it, focusing ONLY on the
following classes:

{TARGET_VULNERABILITIES}

Follow this process exactly.

1. TRIAGE. Read the whole file for context. Identify every place where one of the
   TARGET vulnerabilities is genuinely present AND could be triggered by attacker-
   controlled input. Ignore anything outside the target list. Do not report a
   finding you cannot justify as actually exploitable -- a wrong warning is worse
   than none, because developers stop reading warnings that are usually wrong.

2. EXPLAIN. For each confirmed finding, explain it the way a developer will act
   on: what the vulnerability is, why it matters, and what an attacker would do
   with it. Be specific to this code, not generic.

3. FIX. Produce a corrected version of the FULL file that removes the confirmed
   vulnerabilities while preserving the program's original behavior. Rules:
     - The fixed file must be a drop-in replacement for the original.
     - Do NOT introduce new dependencies or call APIs not already available.
     - Do NOT change behavior, structure, or formatting beyond what the fix needs.
     - Prefer standard, idiomatic fixes: parameterized queries, argument lists
       instead of shell strings, path allow-listing / canonicalization, secrets
       loaded from environment variables, strong hashing (e.g. SHA-256/bcrypt).

ESCAPE HATCHES -- use these instead of guessing:
   - If NONE of the target vulnerabilities are present, write
     "NO TARGET VULNERABILITIES FOUND" in section A and make no changes.
   - If a vulnerability IS present but you cannot fix it without risking a change
     in behavior, do NOT rewrite it. Put it under section E (PROPOSE TO HUMAN)
     and explain what a developer needs to decide.

Respond in EXACTLY this format, with these headers:

A. FINDINGS
<numbered list of confirmed vulnerabilities with CWE id and line, or "NONE">

B. EXPLANATIONS
<for each finding: what it is / why it matters / how it's exploited>

C. COMPATIBILITY RISK
<Low | Medium | High -- how likely your fix changes observable behavior, and why.
 Low = safe to auto-apply. Medium/High = should be reviewed by a human first.>

D. FIXED CODE
<the complete corrected file, or "NO CHANGES">

E. PROPOSE TO HUMAN
<anything you chose NOT to auto-fix, and why, or "NONE">
"""


def analyze_code(code: str, path: str = "<in-memory>") -> tuple[str, str]:
    """
    Run ONE model call against a code string and return (report_text, stop_reason).

    This is the reusable core: fix_file() below calls it for the CLI, and a
    benchmark script can call it directly on test-case strings with no file I/O.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set -- copy engine/.env.example to engine/.env "
            "and paste your key."
        )

    client = anthropic.Anthropic()
    message = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=16000,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Here is the file `{path}`:\n\n```\n{code}\n```",
            }
        ],
    )
    report = "".join(block.text for block in message.content if block.type == "text")
    return report, message.stop_reason


def extract_section(report: str, name: str, next_name: Optional[str]) -> str:
    """Pull the raw text of one lettered section out of the report."""
    if next_name:
        pattern = rf"{re.escape(name)}\s*(.*?)(?:\n\s*{re.escape(next_name)}|\Z)"
    else:
        pattern = rf"{re.escape(name)}\s*(.*)"
    m = re.search(pattern, report, re.DOTALL)
    return m.group(1).strip() if m else ""


def extract_findings_cwes(report: str) -> set[str]:
    """Return the set of CWE ids (e.g. {'CWE-89'}) mentioned in section A."""
    section_a = extract_section(report, "A. FINDINGS", "B. EXPLANATIONS")
    return set(re.findall(r"CWE-\d+", section_a))


def extract_fixed_code(report: str) -> Optional[str]:
    """Pull the code block out of section D. Returns None if there is no fixed code."""
    section = extract_section(report, "D. FIXED CODE", "E. PROPOSE TO HUMAN")
    block = re.search(r"```[^\n]*\n(.*)\n\s*```", section, re.DOTALL)
    return block.group(1) + "\n" if block else None


def fix_file(path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        code = f.read()

    print(f"--- Analyzing: {path} ---\n")
    print(code)
    print("--- Running AI Evaluator Engine ---\n")

    report, stop_reason = analyze_code(code, path=path)
    print(report)

    # Never touch the input file -- write the fixed code and the report to new files
    # in output/, timestamped so earlier test runs aren't overwritten.
    source = Path(path)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    OUTPUT_DIR.mkdir(exist_ok=True)

    report_path = OUTPUT_DIR / f"{source.stem}_report_{stamp}.txt"
    report_path.write_text(report, encoding="utf-8")
    print(f"\n[saved] Report: {report_path}", file=sys.stderr)

    fixed_code = extract_fixed_code(report)
    if fixed_code is None:
        print("[saved] No fixed code file (model reported NO CHANGES, or section D "
              "could not be parsed).", file=sys.stderr)
    else:
        fixed_path = OUTPUT_DIR / f"{source.stem}_fixed_{stamp}{source.suffix}"
        fixed_path.write_text(fixed_code, encoding="utf-8")
        print(f"[saved] Fixed code: {fixed_path}", file=sys.stderr)

    if stop_reason == "max_tokens":
        print("\n[warning] Output was cut off at max_tokens -- the fixed code may be incomplete.",
              file=sys.stderr)
    elif stop_reason == "refusal":
        print("\n[warning] The model declined this request.", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fixer.py <path-to-code-file>")
        sys.exit(1)
    try:
        fix_file(sys.argv[1])
    except anthropic.AuthenticationError:
        print("Invalid or missing API key -- set ANTHROPIC_API_KEY in engine/.env", file=sys.stderr)
        sys.exit(1)
