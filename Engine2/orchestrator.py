"""
Orchestrator: runs stages 1-5 over one case, with the repair/safety retry loop.
==============================================================================

Job
---
Glue, and only glue. Every decision belongs to a stage; this file decides
nothing except when to stop retrying.

    1. detect                                       -> findings
    2. triage                                       -> reported (verdict "real")
       nothing reported -> stage 5 says "no_action", done
    3. repair(attempt N, feedback from attempt N-1) -> fix
    4. verify(fix)                                  -> safety
       safety.ok  -> stop
       otherwise  -> feed safety.feedback_for_repair back into step 3,
                     up to cfg.max_repair_attempts
    5. decide                                       -> Decision

Contract
--------
    run_case(case: Case, llm: LLM, cfg=CONFIG) -> CaseResult
    run_cases(cases, llm, cfg=CONFIG, on_case=None) -> list[CaseResult]

Owner: ____ (shared file -- changes need a reviewed PR)

Known gaps
----------
- Serial. 30 cases x up to 3 attempts, each running pytest twice, is minutes.
  Parallelising per case is safe (each case gets its own temp dir) and is the
  obvious first task.
- Retries always come from the LAST attempt's feedback only; earlier attempts
  are recorded but never shown to the model again.
- A crash in any stage is caught per case and recorded in `CaseResult.error`, so
  one bad case cannot kill a run -- but nothing retries it either.
"""

from __future__ import annotations

from typing import Callable, Optional

from config import CONFIG, Config
from llm import LLM
from models import Case, CaseResult
from stages.decide import decide
from stages.detect import detect
from stages.repair import repair
from stages.safety import verify
from stages.triage import triage


def run_case(case: Case, llm: LLM, cfg: Config = CONFIG) -> CaseResult:
    """The whole pipeline for one case."""
    result = CaseResult(case_id=case.case_id, category=case.category)

    try:
        # --- stage 1 ---------------------------------------------------------
        result.findings = detect(case, cfg)

        # --- stage 2 ---------------------------------------------------------
        result.triaged = triage(case, result.findings, llm, cfg)
        confirmed = [t for t in result.triaged if t.is_real]

        if not confirmed:
            result.decision = decide(case, result.triaged, None, None, cfg)
            return result

        # --- stages 3 + 4, with the retry loop -------------------------------
        feedback: Optional[str] = None
        for attempt in range(1, cfg.max_repair_attempts + 1):
            fix = repair(case, confirmed, llm, cfg, feedback=feedback, attempt=attempt)
            result.fixes.append(fix)

            if fix.no_fix_possible or not fix.has_code:
                break

            safety = verify(case, fix, cfg)
            result.safety.append(safety)

            if safety.ok:
                break
            feedback = safety.feedback_for_repair

            # In offline mode repair cannot change its answer, so retrying is
            # just burning test runs.
            if llm.offline:
                break

        # --- stage 5 ---------------------------------------------------------
        result.decision = decide(case, result.triaged,
                                 result.fixes[-1] if result.fixes else None,
                                 result.final_safety, cfg)

    except Exception as error:                          # noqa: BLE001
        result.error = f"{type(error).__name__}: {error}"
        result.decision = decide(case, result.triaged, None, None, cfg)
        result.decision.reason = f"pipeline error: {result.error}"

    return result


def run_cases(cases: list[Case],
              llm: LLM,
              cfg: Config = CONFIG,
              on_case: Optional[Callable[[CaseResult], None]] = None) -> list[CaseResult]:
    """Run every case in order. `on_case` is called after each one, for progress output."""
    results = []
    for case in cases:
        result = run_case(case, llm, cfg)
        results.append(result)
        if on_case:
            on_case(result)
    return results
