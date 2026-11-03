"""
STAGE 2 -- TRIAGE + EXPLAIN  (LLM)
==================================

Job
---
For each finding from stage 1, decide whether it is really exploitable or a
false alarm, and for the real ones write the explanation a developer acts on:
what it is, why it matters, how it is exploited.

Stage 1 over-flags on purpose, so this stage is where precision comes from.

How a case is processed
-----------------------
  1. STRUCTURAL PRE-FILTER, no model call. A finding whose lines are an import
     statement cannot be a sink, so it is cleared outright. This is what bandit's
     B404 (`import subprocess` reported as CWE-78) produces, and it was every
     false positive left in the last live run.
  2. MERGE findings that describe one flaw -- same CWE, overlapping lines -- so
     two detectors reporting one construct cost one judgement. This is what the
     AST supplement produces next to bandit, and it is a judgement unit only:
     every input finding still gets its own entry out.
  3. ONE BATCHED CALL for everything else in the file. The model gets the file
     once, the reference material for the CWEs in play, and all the findings
     together, and answers with one block per finding. Judging them side by side
     is also how the real flaw gets told apart from the safe look-alike a few
     lines below it.
  4. REASSEMBLY, per-group fail-safe. Output is one entry per input finding, in
     input order, whichever path each one took. A kept finding whose explanation
     came back thin is flagged in `notes` and kept.

Two rules that must not be changed without a PR:
  - There is a "NOT VULNERABLE" escape hatch. The model is allowed, and asked,
    to clear a finding it cannot justify as exploitable.
  - IF THE MODEL GIVES NO USABLE VERDICT, THE FINDING IS KEPT. An unparseable
    reply, an API hiccup or an empty answer must never silently delete a
    finding -- failing safe here means over-reporting, not under-reporting.
    This is per finding, not per call: one malformed block in a batch must not
    affect its neighbours.

Contract
--------
    triage(case: Case, findings: list[Finding], llm: LLM, cfg=CONFIG)
        -> list[TriagedFinding]        # same length and order as `findings`

Owner: ____

Owns the number: FALSE-POSITIVE RATE.

Known gaps
----------
- The model sees the whole file but no cross-file context and no test results,
  so "is this reachable from untrusted input?" is a judgement from source alone.
- Verdict parsing is a regex over each block's first `VERDICT:` line. A reply
  that argues its way to a verdict in prose is treated as unparseable, and
  therefore kept.
- The structural pre-filter knows exactly one pattern (import lines). Anything
  else bandit reports on a line that cannot be a sink still costs a judgement.
- Merging groups only findings whose line ranges overlap. The same flaw reported
  on two ranges that do not touch -- the sink on one line, the helper that built
  the value twenty lines up -- is still charged twice.
- After merging, one bad judgement lands on every member of its group rather
  than on one finding.
- Explanation quality is flagged, not measured: `notes` records which fields came
  back empty, but no number anywhere reflects it. The metric belongs in stage 5.
- The reference material is a fixed set of per-CWE files in ../references. It is
  not retrieved from MITRE, carries no CVE text, and is deliberately written from
  the weakness rather than from the dataset's oracles.
- Offline mode keeps every finding, including the import-line ones, because
  "offline keeps everything" is the documented contract for the free run.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from config import CONFIG, Config
from llm import INJECTION_RULES, LLM, numbered, wrap_untrusted
from models import Case, Explanation, Finding, TriagedFinding

REFERENCES_DIR = Path(__file__).resolve().parent.parent / "references"

SYSTEM_PROMPT = """\
You are a senior application security engineer reviewing the static-analysis
findings in ONE Python file. The scanner that produced them over-reports on
purpose: your job is to keep the findings a developer should act on and clear
the rest.

For each finding, decide whether the reported line really is an instance of the
named CWE that an attacker could trigger with untrusted input.

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

Several findings in one file often describe the same sink, or one real flaw and
one safe look-alike. Judge each on its own line, and use the others for context.

Respond with ONE block per finding, in the order they were given, and nothing
else. Use the number the finding was given:

FINDING 1
VERDICT: VULNERABLE | NOT VULNERABLE
WHAT: <one or two sentences: what the vulnerability is, in this code>
WHY: <why it matters here -- what an attacker gains>
EXPLOIT: <the concrete input or step an attacker would use>

FINDING 2
VERDICT: ...
WHAT: ...
WHY: ...
EXPLOIT: ...

If the verdict is NOT VULNERABLE, put the reason the code is safe in WHAT and
write "n/a" in WHY and EXPLOIT. Emit a block for every finding, even if your
verdict is the same for several of them.
"""

_VERDICT = re.compile(r"^\s*VERDICT\s*:\s*(NOT\s+VULNERABLE|VULNERABLE)", re.I | re.M)
_FINDING_HEADER = re.compile(r"^[ \t]*FINDING[ \t]+(\d+)[^\n]*$", re.I | re.M)

IMPORT_NOTE = "cleared without a call: finding is on an import statement, not a sink"
SHARED_NOTE = "verdict shared with the finding at line {line} (same flaw, overlapping lines)"
INCOMPLETE_NOTE = "explanation incomplete: missing "
_NOT_APPLICABLE = {"n/a", "na", "none", "-"}


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


def parse_batch_reply(reply: str, count: int) -> list[tuple[str | None, Explanation]]:
    """One (verdict, explanation) per finding, indexed by the reply's FINDING number.

    Blocks are keyed by the number the model wrote, not by their position, so a
    reply that reorders them still lands on the right findings. A number that
    never appears -- a dropped or truncated block -- yields None, which the
    caller turns into a kept finding.

    One exception: a reply with no FINDING headers at all is read as a single
    verdict when there is exactly one finding to judge, because then there is
    nothing it could be misattributed to. With two or more findings such a reply
    is ambiguous, so every one of them is kept.
    """
    headers = list(_FINDING_HEADER.finditer(reply or ""))
    if not headers and count == 1:
        return [parse_reply(reply)]

    blocks: dict[int, str] = {}
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(reply)
        blocks.setdefault(int(header.group(1)), reply[header.end():end])

    out: list[tuple[str | None, Explanation]] = []
    for number in range(1, count + 1):
        block = blocks.get(number)
        out.append(parse_reply(block) if block is not None else (None, Explanation()))
    return out


def _import_lines(code: str) -> frozenset[int]:
    """Every line occupied by an import statement, or nothing if the file won't parse.

    AST rather than a regex on the source line: `import` inside a docstring or a
    string literal must not count, and these files are untrusted by design.
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


def _structural_verdict(finding: Finding,
                        import_lines: frozenset[int]) -> tuple[str, str] | None:
    """A verdict decidable from the code alone, or None to let the model judge.

    Exactly one pattern: an import statement is not a sink, so nothing reported
    on one can be reached by untrusted input. Everything else is the model's
    call -- the fail-safe direction here is over-reporting.
    """
    if import_lines and finding.line_start in import_lines \
            and finding.line_end in import_lines:
        return "false_alarm", IMPORT_NOTE
    return None


def _batch_tokens(count: int, cfg: Config) -> int:
    """Room for `count` blocks; the old per-finding budget was a flat 1500."""
    return min(cfg.max_tokens, 600 + 400 * count)


def _merge_groups(findings: list[Finding]) -> list[list[int]]:
    """Indices of `findings` grouped per flaw: same CWE, spans that actually overlap.

    Two detectors reporting one construct -- bandit's B608 on the query line and the
    AST supplement on the enclosing call -- is one judgement, not two. Overlap is
    tested raw, with no tolerance padding: padding would risk pulling a real flaw and
    a safe look-alike a few lines below it into the same group.
    """
    groups: list[list[int]] = []
    for index, finding in enumerate(findings):
        for group in groups:
            if findings[group[0]].cwe == finding.cwe and any(
                    finding.line_start <= findings[other].line_end
                    and findings[other].line_start <= finding.line_end
                    for other in group):
                group.append(index)
                break
        else:
            groups.append([index])
    return groups


def _representative(findings: list[Finding], group: list[int]) -> int:
    """The widest span in the group, so the model sees the whole construct."""
    return max(group, key=lambda i: (findings[i].line_end - findings[i].line_start,
                                     -findings[i].line_start))


def _explanation_gaps(explanation: Explanation) -> str:
    """A note naming the fields a kept finding failed to explain, or "".

    The verdict is not touched: a thin explanation is a reporting defect, not grounds
    for dropping a finding. Only applied to findings the model actually judged real --
    a fail-safe keep already says why it was kept.
    """
    missing = []
    if not explanation.what.strip():
        missing.append("WHAT")
    for name, value in (("WHY", explanation.why),
                        ("EXPLOIT", explanation.how_exploited)):
        text = value.strip().lower().rstrip(".")
        if not text or text in _NOT_APPLICABLE:
            missing.append(name)
    return INCOMPLETE_NOTE + ", ".join(missing) if missing else ""


def _reference_text(cwe: str) -> str:
    """One CWE's reference file, cached; "" when there isn't one."""
    if cwe not in _REFERENCE_CACHE:
        try:
            _REFERENCE_CACHE[cwe] = (REFERENCES_DIR / f"{cwe}.md").read_text(
                encoding="utf-8").strip()
        except OSError:
            _REFERENCE_CACHE[cwe] = ""
    return _REFERENCE_CACHE[cwe]


_REFERENCE_CACHE: dict[str, str] = {}


def _reference_block(cwes: list[str]) -> str:
    """Trusted reference material for the CWEs in play, or "" if there is none.

    Grounds the explanations. It goes in the SYSTEM prompt: the user message is where
    INJECTION_RULES has just declared everything between the markers untrusted.
    """
    parts = [text for text in (_reference_text(cwe) for cwe in sorted(set(cwes))) if text]
    if not parts:
        return ""
    return ("\n\nREFERENCE MATERIAL -- trusted, and not part of the file under analysis.\n"
            "Use it to ground your explanations. Judge the code on how it behaves.\n\n"
            + "\n\n".join(parts) + "\n")


def build_user_message(case: Case, findings: list[Finding]) -> str:
    """The user turn: every finding to judge, then the file once, as untrusted data."""
    blocks = []
    for number, finding in enumerate(findings, 1):
        blocks.append(
            f"FINDING TO JUDGE {number}\n"
            f"  CWE: {finding.cwe}\n"
            f"  lines: {finding.line_start}-{finding.line_end}\n"
            f"  detector: {finding.detector} {finding.rule_id}\n"
            f"  scanner message: {finding.message}"
        )
    return ("\n\n".join(blocks) + "\n\n"
            + wrap_untrusted(numbered(case.code), path=f"{case.case_id}/app.py"))


def triage(case: Case,
           findings: list[Finding],
           llm: LLM,
           cfg: Config = CONFIG) -> list[TriagedFinding]:
    """Stage 2 entry point. Returns one TriagedFinding per input finding, in order."""
    if not findings:
        return []

    # OFFLINE: keep everything, so the pipeline runs end to end for free.
    if llm.offline:
        return [
            TriagedFinding(
                finding=finding, verdict="real",
                explanation=Explanation(
                    what=f"{finding.cwe} reported by {finding.detector} "
                         f"{finding.rule_id} at line {finding.line_start}.",
                    why="Offline mode: no triage was performed.",
                    how_exploited="Offline mode: no exploitability analysis.",
                ),
                notes="offline: kept without triage",
            )
            for finding in findings
        ]

    results: list[TriagedFinding | None] = [None] * len(findings)

    # 1. structural clears, no call
    import_lines = _import_lines(case.code)
    to_judge: list[tuple[int, Finding]] = []
    for position, finding in enumerate(findings):
        structural = _structural_verdict(finding, import_lines)
        if structural is None:
            to_judge.append((position, finding))
            continue
        verdict, note = structural
        results[position] = TriagedFinding(
            finding=finding, verdict=verdict,
            explanation=Explanation(what=note, why="n/a", how_exploited="n/a"),
            notes=note,
        )

    # 2. one call for the rest, one judgement per flaw
    if to_judge:
        pending = [finding for _, finding in to_judge]
        groups = _merge_groups(pending)
        speakers = [_representative(pending, group) for group in groups]

        try:
            reply = llm.complete(
                SYSTEM_PROMPT + INJECTION_RULES + _reference_block(
                    [finding.cwe for finding in pending]),
                build_user_message(case, [pending[index] for index in speakers]),
                max_tokens=_batch_tokens(len(groups), cfg),
            )
        except Exception as error:                  # noqa: BLE001 -- fail safe
            note = f"kept: triage call failed ({type(error).__name__}: {error})"
            for position, finding in to_judge:
                results[position] = TriagedFinding(
                    finding=finding, verdict="real", notes=note)
            return [entry for entry in results if entry is not None]

        # 3. reassembly: one entry per input finding, per-group fail-safe
        parsed = parse_batch_reply(reply, len(groups))
        for group_index, group in enumerate(groups):
            verdict, explanation = parsed[group_index]
            speaker = speakers[group_index]
            for member in group:
                position, finding = to_judge[member]
                notes = []
                if member != speaker:
                    notes.append(SHARED_NOTE.format(line=pending[speaker].line_start))
                if verdict is None:
                    notes.append("kept: no usable VERDICT line in the reply")
                elif verdict == "real":
                    gaps = _explanation_gaps(explanation)
                    if gaps:
                        notes.append(gaps)
                results[position] = TriagedFinding(
                    finding=finding,
                    verdict="real" if verdict is None else verdict,
                    explanation=explanation,
                    notes="; ".join(notes),
                    raw_llm=reply,
                )

    return [entry for entry in results if entry is not None]
