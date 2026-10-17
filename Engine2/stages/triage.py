"""
STAGE 2 -- TRIAGE + EXPLAIN  (LLM)
==================================

Job
---
For each finding from stage 1, decide whether it is really exploitable or a
false alarm, and for the real ones write the explanation a developer acts on:
what it is, why it matters, how it is exploited.

Stage 1 over-flags on purpose, so this stage is where precision comes from.

Two rules that must not be changed without a PR:
  - There is a "NOT VULNERABLE" escape hatch. The model is allowed, and asked,
    to clear a finding it cannot justify as exploitable.
  - IF THE MODEL GIVES NO USABLE VERDICT, THE FINDING IS KEPT. An unparseable
    reply, an API hiccup or an empty answer must never silently delete a
    finding -- failing safe here means over-reporting, not under-reporting.

Contract
--------
    triage(case: Case, findings: list[Finding], llm: LLM, cfg=CONFIG)
        -> list[TriagedFinding]        # same length and order as `findings`

Owner: ____

Owns the number: FALSE-POSITIVE RATE.

Known gaps
----------
- One API call per finding. Bandit reports six CWE-89 hits on a single case, so
  this is the most expensive stage by call count; batching all of a file's
  findings into one call is the obvious first task.
- The model sees the whole file but no cross-file context and no test results,
  so "is this reachable from untrusted input?" is a judgement from source alone.
- Verdict parsing is a regex over the first `VERDICT:` line. A reply that argues
  its way to a verdict in prose is treated as unparseable, and therefore kept.
- Nothing de-duplicates findings that are the same flaw reported on two lines;
  each is triaged (and charged) separately.
"""

from __future__ import annotations

import re

from config import CONFIG, Config
from llm import INJECTION_RULES, LLM, numbered, wrap_untrusted
from models import Case, Explanation, Finding, TriagedFinding

SYSTEM_PROMPT = """\
You are a senior application security engineer reviewing ONE static-analysis
finding in a Python file. The scanner that produced it over-reports on purpose:
your job is to keep the findings a developer should act on and clear the rest.

Decide whether the reported line really is an instance of the named CWE that an
attacker could trigger with untrusted input.

Say NOT VULNERABLE when the code is actually safe, for example:
  - the only interpolated value is a module constant or a hard-coded table name,
    and every user value is passed as a bound parameter;
  - a subprocess call passes an argument list with shell=False;
  - a weak hash is used for a cache key or ETag and not for security
    (e.g. usedforsecurity=False);
  - a path is resolved and then checked to stay inside an allowed base
    directory;
  - a secret is read from the environment rather than written in the source.

Say VULNERABLE when untrusted input can reach the dangerous sink, including when
a guard exists but can be bypassed (a blocklist that misses `&&`, a single
`../` strip pass, a prefix check with no separator, quoting that a shell undoes).

Respond in EXACTLY this format and nothing else:

VERDICT: VULNERABLE | NOT VULNERABLE
WHAT: <one or two sentences: what the vulnerability is, in this code>
WHY: <why it matters here -- what an attacker gains>
EXPLOIT: <the concrete input or step an attacker would use>

If the verdict is NOT VULNERABLE, put the reason the code is safe in WHAT and
write "n/a" in WHY and EXPLOIT.
"""

_VERDICT = re.compile(r"^\s*VERDICT\s*:\s*(NOT\s+VULNERABLE|VULNERABLE)", re.I | re.M)


def _field(reply: str, name: str, nexts: tuple[str, ...]) -> str:
    stop = "|".join(nexts) if nexts else r"\Z"
    pattern = rf"^\s*{name}\s*:\s*(.*?)(?=^\s*(?:{stop})\s*:|\Z)" if nexts \
        else rf"^\s*{name}\s*:\s*(.*)"
    match = re.search(pattern, reply, re.I | re.M | re.S)
    return match.group(1).strip() if match else ""


def parse_reply(reply: str) -> tuple[str | None, Explanation]:
    """(verdict or None when unusable, explanation). None means 'keep the finding'."""
    match = _VERDICT.search(reply or "")
    verdict = None
    if match:
        verdict = "false_alarm" if re.match(r"NOT", match.group(1), re.I) else "real"
    return verdict, Explanation(
        what=_field(reply or "", "WHAT", ("WHY", "EXPLOIT")),
        why=_field(reply or "", "WHY", ("EXPLOIT",)),
        how_exploited=_field(reply or "", "EXPLOIT", ()),
    )


def build_user_message(case: Case, finding: Finding) -> str:
    """The user turn: the finding to judge, then the file as untrusted data."""
    return (
        f"FINDING TO JUDGE\n"
        f"  CWE: {finding.cwe}\n"
        f"  lines: {finding.line_start}-{finding.line_end}\n"
        f"  detector: {finding.detector} {finding.rule_id}\n"
        f"  scanner message: {finding.message}\n\n"
        + wrap_untrusted(numbered(case.code), path=f"{case.case_id}/app.py")
    )


def triage(case: Case,
           findings: list[Finding],
           llm: LLM,
           cfg: Config = CONFIG) -> list[TriagedFinding]:
    """Stage 2 entry point. Returns one TriagedFinding per input finding, in order."""
    out: list[TriagedFinding] = []

    for finding in findings:
        # OFFLINE: keep everything, so the pipeline runs end to end for free.
        if llm.offline:
            out.append(TriagedFinding(
                finding=finding, verdict="real",
                explanation=Explanation(
                    what=f"{finding.cwe} reported by {finding.detector} "
                         f"{finding.rule_id} at line {finding.line_start}.",
                    why="Offline mode: no triage was performed.",
                    how_exploited="Offline mode: no exploitability analysis.",
                ),
                notes="offline: kept without triage",
            ))
            continue

        try:
            reply = llm.complete(
                SYSTEM_PROMPT + INJECTION_RULES,
                build_user_message(case, finding),
                max_tokens=1500,
            )
        except Exception as error:                      # noqa: BLE001 -- fail safe
            out.append(TriagedFinding(
                finding=finding, verdict="real",
                notes=f"kept: triage call failed ({type(error).__name__}: {error})",
            ))
            continue

        verdict, explanation = parse_reply(reply)
        if verdict is None:
            out.append(TriagedFinding(
                finding=finding, verdict="real", explanation=explanation,
                notes="kept: no usable VERDICT line in the reply", raw_llm=reply,
            ))
        else:
            out.append(TriagedFinding(
                finding=finding, verdict=verdict, explanation=explanation,
                raw_llm=reply,
            ))

    return out
