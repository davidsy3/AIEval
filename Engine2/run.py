"""
CLI: run the whole pipeline over a dataset and print the three numbers.
=======================================================================

    python run.py ../dataset                 # live: needs ANTHROPIC_API_KEY
    python run.py ../dataset --offline       # free: no API calls at all
    python run.py ../dataset --case case_01_inventory_lookup --case case_13_member_login
    python run.py ../dataset --offline --ast # add the stage-1 AST supplement

Saves the full run (findings, explanations, fixes, test output, decisions) to
results/run_<timestamp>.json.

Owner: ____ (shared file -- changes need a reviewed PR)

Known gaps
----------
- No resume. A run that dies at case 28 is a run you do again from case 01.
- The preflight proves the credential works on ONE small call. It does not
  prove a 16000-token repair call will not hit a rate limit halfway through a
  30-case run.
- Progress output only; no live cost or token counter.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from datetime import datetime
from pathlib import Path

from config import CONFIG
from dataset_loader import load_cases, missing_functional_tests
from llm import PreflightError, build_llm, preflight
from models import CaseResult
from orchestrator import run_cases
from stages.decide import score

RESULTS_DIR = Path(__file__).resolve().parent / "results"


def _percent(value) -> str:
    return "   n/a" if value is None else f"{value * 100:5.1f}%"


def print_report(report: dict, cfg) -> None:
    overall = report["overall"]
    counts = overall["counts"]

    print("\n" + "=" * 72)
    print("THE THREE NUMBERS" + ("   [OFFLINE RUN -- see the note below]" if cfg.offline else ""))
    print("=" * 72)
    print(f"  false-negative rate  {_percent(overall['false_negative_rate'])}   "
          f"({counts['missed']} of {counts['annotated']} annotated vulns not reported)")
    decoy_note = (f", {counts['decoy_hits']} of them on an annotated decoy"
                  if counts["decoy_hits"] else "")
    print(f"  false-positive rate  {_percent(overall['false_positive_rate'])}   "
          f"({counts['spurious']} of {counts['reported']} reported findings had no match"
          f"{decoy_note})")
    print(f"  regression rate      {_percent(overall['regression_rate'])}   "
          f"({counts['fixes_regressed']} of {counts['fixes_judged']} judged fixes broke a passing test)")

    print("\n  per CWE")
    print(f"    {'cwe':<10}{'FN rate':>10}{'FP rate':>10}{'regr':>10}"
          f"{'annotated':>11}{'reported':>10}")
    for cwe, bucket in report["per_cwe"].items():
        c = bucket["counts"]
        print(f"    {cwe:<10}{_percent(bucket['false_negative_rate']):>10}"
              f"{_percent(bucket['false_positive_rate']):>10}"
              f"{_percent(bucket['regression_rate']):>10}"
              f"{c['annotated']:>11}{c['reported']:>10}")

    actions: dict[str, int] = {}
    for case in report["per_case"]:
        actions[case["decision"]] = actions.get(case["decision"], 0) + 1
    print("\n  decisions: " + ", ".join(f"{k}={v}" for k, v in sorted(actions.items())))

    errors = [c for c in report["per_case"] if c["error"]]
    if errors:
        print(f"\n  [!] {len(errors)} case(s) errored:")
        for case in errors:
            print(f"      {case['case_id']}: {case['error']}")

    if cfg.offline:
        print("\n  OFFLINE RUN: triage kept every finding without judging it, and repair\n"
              "  returned the code unchanged at High risk. So the false-positive rate is\n"
              "  raw stage-1 noise, nothing auto-applies, and the regression rate is 0 by\n"
              "  construction. These numbers prove the plumbing works, not the system.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the AI Evaluator pipeline over a dataset.")
    parser.add_argument("cases_dir", help="dataset folder holding case_* dirs and ground_truth.json")
    parser.add_argument("--offline", action="store_true",
                        help="no API calls: triage keeps everything, repair changes nothing")
    parser.add_argument("--ast", action="store_true",
                        help="stage 1 also runs the v0 AST checks (adds CWE-22 coverage)")
    parser.add_argument("--case", action="append", default=[], metavar="CASE_ID",
                        help="run only this case (repeatable)")
    parser.add_argument("--limit", type=int, help="run only the first N cases")
    parser.add_argument("--model", help=f"override the model id (default {CONFIG.model})")
    args = parser.parse_args(argv)

    cfg = dataclasses.replace(
        CONFIG,
        offline=args.offline,
        use_ast_supplement=args.ast,
        model=args.model or CONFIG.model,
    )

    cases = load_cases(args.cases_dir, cfg)
    if args.case:
        wanted = set(args.case)
        cases = [c for c in cases if c.case_id in wanted]
    if args.limit:
        cases = cases[: args.limit]
    if not cases:
        print("No cases matched.", file=sys.stderr)
        return 1

    missing = missing_functional_tests(cases)
    if missing:
        print(f"[!] {len(missing)} case(s) have no test_functional.py, so stage 4 cannot\n"
              f"    compute regressions for them: {', '.join(missing)}", file=sys.stderr)

    llm = build_llm(cfg)
    try:
        preflight(llm)
    except PreflightError as error:
        print(f"\n[!] PREFLIGHT FAILED -- nothing was run.\n\n{error}", file=sys.stderr)
        return 2

    print(f"[run] {len(cases)} case(s) | "
          f"{'OFFLINE' if llm.offline else 'model ' + cfg.model} | "
          f"stage 1: bandit{' + ast' if cfg.use_ast_supplement else ''} | "
          f"max {cfg.max_repair_attempts} repair attempt(s)", file=sys.stderr)

    def progress(result: CaseResult) -> None:
        print(f"  {result.case_id:<30} "
              f"detected={len(result.findings):<3} reported={len(result.reported):<3} "
              f"attempts={len(result.fixes):<2} -> {result.decision.action}"
              f"{'  [ERROR] ' + result.error if result.error else ''}", file=sys.stderr)

    results = run_cases(cases, llm, cfg, on_case=progress)
    report = score(results, cases, cfg)
    print_report(report, cfg)

    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = RESULTS_DIR / f"run_{stamp}.json"
    out.write_text(json.dumps({
        "run": {
            "timestamp": stamp,
            "cases_dir": str(Path(args.cases_dir).resolve()),
            "offline": cfg.offline,
            "model": None if llm.offline else cfg.model,
            "ast_supplement": cfg.use_ast_supplement,
            "max_repair_attempts": cfg.max_repair_attempts,
            "line_tolerance": cfg.line_tolerance,
            "llm_calls": llm.calls,
            "cases_without_functional_tests": missing,
        },
        "report": report,
        "cases": [dataclasses.asdict(r) for r in results],
    }, indent=2, default=str), encoding="utf-8")
    print(f"\n[saved] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
