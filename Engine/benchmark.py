"""
Bare-bones benchmark harness -- sprint 1.
 
For each entry in manifest.json:
  1. read the test file
  2. call analyze_code() (imported from fixer.py) -- one live model call
  3. parse the CWE ids out of section A (FINDINGS)
  4. compare against the manifest's expected_cwes
 
Prints a per-file breakdown plus an overall precision/recall.
This intentionally does NOT check whether the FIX (section D) actually works --
that's a follow-up story once detection numbers look reasonable.
 
Run
---
    cd benchmark
    python run_benchmark.py
"""
 
import json
from pathlib import Path
 
from fixer import analyze_code, extract_findings_cwes
 
HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "test-cases" / "manifest.json"
TEST_DIR = HERE / "test-cases"
 
 
def run():
    manifest = json.loads(MANIFEST_PATH.read_text())
    rows = []
 
    for case in manifest:
        file_path = TEST_DIR / case["file"]
        code = file_path.read_text(encoding="utf-8")
 
        report, stop_reason = analyze_code(code, path=case["file"])
        found = extract_findings_cwes(report)
        expected = set(case["expected_cwes"])
 
        rows.append({
            "file": case["file"],
            "expected": expected,
            "found": found,
            "true_positive": found & expected,
            "false_negative": expected - found,
            "false_positive": found - expected,
            "stop_reason": stop_reason,
        })
 
    print(f"{'file':<20} {'expected':<15} {'found':<15} {'TP':<10} {'FN':<10} {'FP':<10}")
    print("-" * 80)
    for r in rows:
        print(
            f"{r['file']:<20} "
            f"{','.join(sorted(r['expected'])) or '-':<15} "
            f"{','.join(sorted(r['found'])) or '-':<15} "
            f"{','.join(sorted(r['true_positive'])) or '-':<10} "
            f"{','.join(sorted(r['false_negative'])) or '-':<10} "
            f"{','.join(sorted(r['false_positive'])) or '-':<10}"
        )
 
    tp = sum(len(r["true_positive"]) for r in rows)
    fn = sum(len(r["false_negative"]) for r in rows)
    fp = sum(len(r["false_positive"]) for r in rows)
 
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
 
    print("-" * 80)
    print(f"Overall  TP={tp}  FN={fn}  FP={fp}  precision={precision:.2f}  recall={recall:.2f}")
 
 
if __name__ == "__main__":
    run()
 
