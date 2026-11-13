"""
Regression target check: is the latest run within the project's regression goal?
================================================================================

    python check_regression.py          # reads the newest results/run_*.json

Target (../README.md): at least 90% of successful repairs pass the existing
functional tests without regression -- a regression rate of at most 10%.

Definitions
-----------
- successful repair: a case's FINAL attempt whose security oracle passed
  (`security_verdict` is true). A re-scan-only "vuln gone" does not count.
- regressed: that attempt has a non-empty `regressions` list (functional tests
  that passed on the original and fail on the fix). Decoy breaks are not part
  of this target.
- excluded: successful repairs whose functional baseline never ran (no
  test_functional.py), since they cannot show a regression.
- rate = regressed / (successful - excluded). With nothing left to count it is
  n/a: neither a pass nor a fail.

Exit code: 0 PASS, 1 FAIL, 2 N/A.

Owner: ____

Known gaps
----------
- The engine's own `regression_rate` (stage 5) counts every judged fix and
  decoy breaks too, so the two numbers differ by design.
- An offline run never has a successful repair (repair returns the code
  unchanged), so it always reports N/A.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "results"
TARGET = 0.10                      # at most 10% of successful repairs may regress


def latest_results(results_dir: Path = RESULTS_DIR) -> Path | None:
    """The newest run file. `run_YYYYMMDD-HHMMSS.json` names sort by time."""
    runs = sorted(results_dir.glob("run_*.json"))
    return runs[-1] if runs else None


def check(data: dict, target: float = TARGET) -> dict:
    """Count successful repairs and regressions in one results file."""
    successful, excluded, regressed = [], [], []
    for case in data["cases"]:
        if not case["safety"]:
            continue
        final = case["safety"][-1]
        if final.get("security_verdict") is not True:
            continue
        successful.append(case["case_id"])
        if not final["functional_baseline"]["ran"]:
            excluded.append(case["case_id"])
        elif final["regressions"]:
            regressed.append(case["case_id"])

    counted = len(successful) - len(excluded)
    rate = len(regressed) / counted if counted else None
    verdict = "N/A" if rate is None else ("PASS" if rate <= target else "FAIL")
    return {"successful": successful, "excluded": excluded, "regressed": regressed,
            "counted": counted, "rate": rate, "verdict": verdict}


def main() -> int:
    path = latest_results()
    if path is None:
        print(f"No results/run_*.json in {RESULTS_DIR}. Run run.py first.", file=sys.stderr)
        return 2
    data = json.loads(path.read_text(encoding="utf-8"))
    result = check(data)
    run = data["run"]

    print(f"results:  {path.name}  ({'OFFLINE' if run.get('offline') else 'live'}, "
          f"stage 4: {run.get('stage4_isolation', 'unknown')})")
    print(f"successful repairs (security oracle passed): {len(result['successful'])}")
    print(f"  excluded (no functional baseline):         {len(result['excluded'])}")
    print(f"  counted:                                   {result['counted']}")
    print(f"  regressed:                                 {len(result['regressed'])}")
    rate = "n/a" if result["rate"] is None else f"{result['rate'] * 100:.1f}%"
    print(f"regression rate: {rate}   target: <= {TARGET * 100:.0f}%   -> {result['verdict']}")
    for case_id in result["regressed"]:
        print(f"  regressed: {case_id}")
    if result["verdict"] == "N/A":
        print("  (no successful repairs to judge"
              + (": an offline run never repairs anything" if run.get("offline") else "")
              + ")")
    return {"PASS": 0, "FAIL": 1, "N/A": 2}[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
