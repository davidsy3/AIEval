"""
STAGE 5 -- DECIDE + REPORT
==========================

Job
---
Two things:

  1. DECIDE, per case: auto-apply the fix, or propose it to a human.
     Auto-apply requires ALL THREE of
         risk == "Low"              (stage 3's own compatibility rating)
         safety.tests_pass          (green, no regression, no safe code broken)
         safety.vuln_gone           (the flaw is actually gone)
     Anything else is proposed to a human. There is no fourth option, and a
     missing signal is never read as a pass.

  2. SCORE the run against the dataset's annotations and report three numbers,
     overall and per CWE:
         false-negative rate = annotated vulns not reported / all annotated vulns
         false-positive rate = reported findings with no matching annotation
                               / all reported findings
         regression rate     = fixes that break previously passing tests
                               / fixes judged
     "Reported" means findings that survived stage 2. Matching is the dataset's
     own rule (dataset/README.md): same CWE, and the finding's line range
     overlaps the annotation's primary span or any of its `related_lines`,
     widened by cfg.line_tolerance (+/-3). Matching is ONE TO ONE -- one finding
     can only account for one annotated vulnerability, and vice versa.

Contract
--------
    decide(case, triaged, fix, safety, cfg=CONFIG) -> Decision
    score(results: list[CaseResult], cases: list[Case], cfg=CONFIG) -> dict
    match(reported, annotations, cfg) -> (pairs, unmatched_findings, unmatched_anns)

Owner: ____

Owns the number: the REPORT itself -- all three numbers and the per-CWE split.

Known gaps
----------
- One-to-one matching is greedy by line distance, not optimal (no Hungarian
  assignment). With several same-CWE findings crowded around one annotation the
  pairing can be suboptimal; it never changes a matched/unmatched count by more
  than the crowding, but it is not provably minimal.
- A false positive is counted per FINDING, so stage 1 reporting the same flaw on
  six lines costs six false positives. That is intentional (it is what a
  developer sees) but it makes the rate look worse than "fraction of files with
  a wrong warning".
- Regression rate is per CASE, not per test: a fix that breaks four tests counts
  once. Per-CWE regression is attributed by the CWEs the fix addressed, so a
  multi-CWE fix is charged to every CWE it touched.
- Decoy hits are reported as a diagnostic, not folded into the headline numbers.
  Under the dataset's rule they are already counted as false positives.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Optional

from config import CONFIG, Config
from models import (Annotation, Case, CaseResult, Decision, Finding, Fix,
                    SafetyResult, TriagedFinding)


# --- matching ----------------------------------------------------------------

def _overlaps(finding: Finding, annotation: Annotation, tolerance: int) -> bool:
    f_start, f_end = finding.spans(0)
    return any(f_start <= a_end and a_start <= f_end
               for a_start, a_end in annotation.spans(tolerance))


def match(reported: list[Finding],
          annotations: list[Annotation],
          cfg: Config = CONFIG) -> tuple[list[tuple[Finding, Annotation]],
                                         list[Finding], list[Annotation]]:
    """One-to-one pairing of findings to annotations: same CWE, overlapping lines."""
    candidates = [
        (abs(f.line_start - a.line_start), i, j)
        for i, f in enumerate(reported)
        for j, a in enumerate(annotations)
        if f.cwe == a.cwe and _overlaps(f, a, cfg.line_tolerance)
    ]
    candidates.sort()

    used_f: set[int] = set()
    used_a: set[int] = set()
    pairs = []
    for _, i, j in candidates:
        if i in used_f or j in used_a:
            continue
        used_f.add(i)
        used_a.add(j)
        pairs.append((reported[i], annotations[j]))

    return (pairs,
            [f for i, f in enumerate(reported) if i not in used_f],
            [a for j, a in enumerate(annotations) if j not in used_a])


# --- the decision ------------------------------------------------------------

def decide(case: Case,
           triaged: list[TriagedFinding],
           fix: Optional[Fix],
           safety: Optional[SafetyResult],
           cfg: Config = CONFIG) -> Decision:
    """Auto-apply only on Low risk + green tests + vuln gone. Otherwise a human looks."""
    confirmed = [t for t in triaged if t.is_real]

    if not confirmed:
        return Decision(action="no_action", risk="Low",
                        reason="nothing survived triage" if triaged
                               else "no findings from the detector")

    if fix is None or safety is None:
        return Decision(action="propose_to_human", risk="High",
                        reason="no repair attempt was made")

    if fix.no_fix_possible:
        return Decision(action="propose_to_human", risk=fix.risk, attempt_used=fix.attempt,
                        reason="repair reported NO FIX POSSIBLE")

    if not fix.has_code:
        return Decision(action="propose_to_human", risk=fix.risk, attempt_used=fix.attempt,
                        reason="repair returned no code to apply")

    blockers = []
    if fix.risk != "Low":
        blockers.append(f"compatibility risk is {fix.risk}")
    if not safety.syntax_ok:
        blockers.append("fixed file does not parse")
    if safety.regressions:
        blockers.append(f"{len(safety.regressions)} functional test(s) regressed")
    if safety.decoy_breaks:
        blockers.append(f"{len(safety.decoy_breaks)} previously-safe test(s) broken")
    if not safety.functional_after.passed:
        blockers.append("functional tests do not pass")
    if not safety.vuln_gone:
        blockers.append("the vulnerability is still reported")

    if blockers:
        return Decision(action="propose_to_human", risk=fix.risk,
                        attempt_used=fix.attempt, reason="; ".join(blockers))

    return Decision(action="auto_apply", risk=fix.risk, attempt_used=fix.attempt,
                    reason="Low risk, tests green, vulnerability gone")


# --- the report --------------------------------------------------------------

def _rate(numerator: int, denominator: int) -> Optional[float]:
    return round(numerator / denominator, 4) if denominator else None


def _blank() -> dict:
    return {"annotated": 0, "missed": 0, "reported": 0, "spurious": 0,
            "fixes_judged": 0, "fixes_regressed": 0, "decoy_hits": 0}


def score(results: list[CaseResult],
          cases: list[Case],
          cfg: Config = CONFIG) -> dict:
    """The three numbers, overall and per CWE, plus the per-case detail."""
    by_id = {c.case_id: c for c in cases}
    overall = _blank()
    per_cwe: dict[str, dict] = defaultdict(_blank)
    per_case = []

    for result in results:
        case = by_id.get(result.case_id)
        if case is None:
            continue

        reported = result.reported
        pairs, spurious, missed = match(reported, case.vulns, cfg)

        # Diagnostic: which wrong findings landed on an annotated decoy?
        decoy_hits = [f for f in spurious
                      if any(_overlaps(f, d, cfg.line_tolerance)
                             for d in case.decoys if d.cwe == f.cwe)]

        # A fix is "judged" when stage 4 actually ran tests on it; it "regressed"
        # when a test that passed on the original file fails on the fix.
        safety = result.final_safety
        judged = bool(safety and safety.applied and safety.functional_baseline.ran)
        broke = sorted(set((safety.regressions if safety else [])
                           + (safety.decoy_breaks if safety else [])))
        regressed = bool(judged and broke)

        overall["annotated"] += len(case.vulns)
        overall["missed"] += len(missed)
        overall["reported"] += len(reported)
        overall["spurious"] += len(spurious)
        overall["decoy_hits"] += len(decoy_hits)
        overall["fixes_judged"] += int(judged)
        overall["fixes_regressed"] += int(regressed)

        for annotation in case.vulns:
            per_cwe[annotation.cwe]["annotated"] += 1
        for annotation in missed:
            per_cwe[annotation.cwe]["missed"] += 1
        for finding in reported:
            per_cwe[finding.cwe]["reported"] += 1
        for finding in spurious:
            per_cwe[finding.cwe]["spurious"] += 1
        for finding in decoy_hits:
            per_cwe[finding.cwe]["decoy_hits"] += 1
        # A multi-CWE fix is charged to every CWE it addressed.
        fix = result.fixes[-1] if result.fixes else None
        for cwe in (fix.addressed_cwes if fix else []):
            per_cwe[cwe]["fixes_judged"] += int(judged)
            per_cwe[cwe]["fixes_regressed"] += int(regressed)

        per_case.append({
            "case_id": result.case_id,
            "category": case.category,
            "annotated": [a.ann_id for a in case.vulns],
            "detected": len(result.findings),
            "reported": len(reported),
            "matched": [{"finding": f.finding_id, "vuln": a.ann_id} for f, a in pairs],
            "missed": [{"vuln": a.ann_id, "cwe": a.cwe, "line": a.line_start,
                        "subtlety": a.subtlety} for a in missed],
            "spurious": [{"cwe": f.cwe, "line": f.line_start, "rule": f.rule_id,
                          "on_decoy": f in decoy_hits} for f in spurious],
            "attempts": len(result.fixes),
            "fix_judged": judged,
            "broke_tests": broke,
            "decision": result.decision.action,
            "decision_reason": result.decision.reason,
            "error": result.error,
        })

    def rates(bucket: dict) -> dict:
        return {
            "false_negative_rate": _rate(bucket["missed"], bucket["annotated"]),
            "false_positive_rate": _rate(bucket["spurious"], bucket["reported"]),
            "regression_rate": _rate(bucket["fixes_regressed"], bucket["fixes_judged"]),
            "counts": bucket,
        }

    return {
        "overall": rates(overall),
        "per_cwe": {cwe: rates(per_cwe[cwe]) for cwe in sorted(per_cwe)},
        "per_case": per_case,
    }
