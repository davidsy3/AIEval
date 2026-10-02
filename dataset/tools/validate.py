"""Validate the dev dataset: oracles, ground truth, composition and hint words.

Usage:
    .venv/bin/python tools/validate.py            # full check (expects all 30 cases)
    .venv/bin/python tools/validate.py --partial  # skip the 16/8/6 composition check
    .venv/bin/python tools/validate.py case_01_inventory_lookup case_17_note_sync

Exits non-zero if any check fails.
"""

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable
TIMEOUT = 180

PRIMARY_CWES = {"CWE-89", "CWE-78", "CWE-22", "CWE-327"}
SECONDARY_CWES = {"CWE-798"}
CATEGORIES = {"single": 16, "multi": 8, "clean": 6}
SUBTLETIES = {"obvious", "moderate", "subtle"}
FIX_RISKS = {"Low", "Medium", "High"}
REQUIRED_FILES = ["app.py", "test_functional.py", "test_security.py", "reference_fix.py", "conftest.py"]
HINT_WORDS = ["vuln", "unsafe", "insecure", "inject", "sanitize", "todo", "fixme", "# safe", "exploit"]
TARGETS = ["app", "reference_fix"]


# --- helpers -----------------------------------------------------------------

def run_pytest(case_dir, target, test_file):
    """Run one test file against one target. Returns (ok, {test_name: passed}, output)."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.xml"
        env = dict(os.environ, TARGET_MODULE=target, PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.run(
            [PYTHON, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             f"--junitxml={report}", test_file],
            cwd=case_dir, env=env, capture_output=True, text=True, timeout=TIMEOUT,
        )
        results = {}
        if report.exists():
            for tc in ET.parse(report).getroot().iter("testcase"):
                failed = any(child.tag in ("failure", "error") for child in tc)
                skipped = any(child.tag == "skipped" for child in tc)
                results[tc.get("name")] = not failed and not skipped
    return proc.returncode == 0, results, proc.stdout + proc.stderr


def import_cleanly(case_dir, module):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        [PYTHON, "-c", f"import {module}"], cwd=case_dir, env=env,
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        return f"{module}.py failed to import: {proc.stderr.strip().splitlines()[-1:]}"
    if proc.stdout.strip():
        return f"{module}.py prints on import (side effect)"
    return None


def function_spans(tree):
    """Map 'func' and 'Class.method' to (first_line, last_line), decorators included."""
    spans = {}

    def visit(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}{child.name}"
                start = min([child.lineno] + [d.lineno for d in child.decorator_list])
                if not isinstance(child, ast.ClassDef):
                    spans[name] = (start, child.end_lineno)
                visit(child, f"{name}.")
    visit(tree, "")
    return spans


def module_level_ok(tree, start, end):
    """True if [start, end] is not inside any top-level def or class."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not (end < node.lineno or start > node.end_lineno):
                return False
    return True


def check_location(tree, spans, loc, label):
    fn, start, end = loc.get("function"), loc.get("line_start"), loc.get("line_end")
    if not isinstance(start, int) or not isinstance(end, int) or start > end:
        return f"{label}: bad line range {start}..{end}"
    if fn == "<module>":
        if not module_level_ok(tree, start, end):
            return f"{label}: lines {start}-{end} are not at module level"
        return None
    if fn not in spans:
        return f"{label}: function {fn!r} not found in app.py"
    lo, hi = spans[fn]
    if not (lo <= start and end <= hi):
        return f"{label}: lines {start}-{end} fall outside {fn} ({lo}-{hi})"
    return None


def test_names(path):
    tree = ast.parse(path.read_text())
    return {n.name for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")}


def non_stdlib_imports(path):
    tree = ast.parse(path.read_text())
    bad = set()
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        for name in names:
            top = name.split(".")[0]
            if top not in sys.stdlib_module_names:
                bad.add(top)
    return sorted(bad)


# --- per-case validation -------------------------------------------------------

def validate_case(case):
    """Return (row, problems) where row maps column -> PASS/FAIL/-."""
    case_dir = ROOT / case["case_id"]
    problems = []
    row = {}

    missing = [f for f in REQUIRED_FILES if not (case_dir / f).exists()]
    if missing:
        return {"files": "FAIL"}, [f"missing files: {', '.join(missing)}"]
    row["files"] = "PASS"

    app_src = (case_dir / "app.py").read_text()
    tree = ast.parse(app_src)
    spans = function_spans(tree)

    # static checks on app.py
    static = []
    n_lines = len(app_src.splitlines())
    if not 40 <= n_lines <= 150:
        static.append(f"app.py has {n_lines} lines (want 40-150)")
    lowered = app_src.lower()
    static += [f"hint word {w!r} in app.py" for w in HINT_WORDS if w in lowered]
    for f in ("app.py", "reference_fix.py"):
        bad = non_stdlib_imports(case_dir / f)
        if bad:
            static.append(f"{f} imports non-stdlib: {', '.join(bad)}")
    row["static"] = "FAIL" if static else "PASS"
    problems += static

    # 1. imports
    errs = [e for e in (import_cleanly(case_dir, m) for m in TARGETS) if e]
    row["import"] = "FAIL" if errs else "PASS"
    problems += errs
    if errs:
        return row, problems

    # 2. functional oracle on both targets
    func_ok = True
    for target in TARGETS:
        ok, _, out = run_pytest(case_dir, target, "test_functional.py")
        if not ok:
            func_ok = False
            problems.append(f"test_functional fails on {target}:\n" + indent_tail(out))
    row["functional"] = "PASS" if func_ok else "FAIL"

    # 3. security oracle
    vulns, decoys = case.get("vulnerabilities", []), case.get("decoys", [])
    sec_tests = test_names(case_dir / "test_security.py")
    vuln_tests = {v["security_test"].split("::")[-1] for v in vulns}
    decoy_tests = {d["security_test"].split("::")[-1] for d in decoys}
    _, app_res, app_out = run_pytest(case_dir, "app", "test_security.py")
    _, ref_res, ref_out = run_pytest(case_dir, "reference_fix", "test_security.py")
    sec_problems = []
    for t in sorted(sec_tests):
        if t in vuln_tests:
            if app_res.get(t, True):
                sec_problems.append(f"{t} should FAIL on app but passed (or did not run)")
        elif app_res.get(t) is not True:
            sec_problems.append(f"{t} should PASS on app")
        if ref_res.get(t) is not True:
            sec_problems.append(f"{t} should PASS on reference_fix")
    if sec_problems and any("reference_fix" in p for p in sec_problems):
        sec_problems.append("reference_fix output:\n" + indent_tail(ref_out))
    row["security"] = "FAIL" if sec_problems else "PASS"
    problems += sec_problems

    # 4 + 5. ground-truth locations and test references
    gt = []
    for entry, kind in [(v, "vuln") for v in vulns] + [(d, "decoy") for d in decoys]:
        label = entry.get("vuln_id") or entry.get("decoy_id")
        for loc in [entry] + entry.get("related_lines", []):
            err = check_location(tree, spans, loc, label)
            if err:
                gt.append(err)
        test_file, _, test_name = entry.get("security_test", "").partition("::")
        if test_file != "test_security.py" or test_name not in sec_tests:
            gt.append(f"{label}: security_test {entry.get('security_test')!r} does not exist")
        if kind == "vuln":
            if entry.get("subtlety") not in SUBTLETIES:
                gt.append(f"{label}: bad subtlety {entry.get('subtlety')!r}")
            if entry.get("expected_fix_risk") not in FIX_RISKS:
                gt.append(f"{label}: bad expected_fix_risk")
    unreferenced = sec_tests - vuln_tests - decoy_tests
    gt += [f"test_security.py::{t} is not referenced by ground truth" for t in sorted(unreferenced)]
    row["ground_truth"] = "FAIL" if gt else "PASS"
    problems += gt

    return row, problems


def indent_tail(text, n=25):
    lines = text.strip().splitlines()[-n:]
    return "\n".join("        " + line for line in lines)


# --- dataset-level composition ----------------------------------------------

def check_composition(cases):
    problems = []
    cats = Counter(c["category"] for c in cases)
    for cat, want in CATEGORIES.items():
        if cats.get(cat, 0) != want:
            problems.append(f"{cat}: {cats.get(cat, 0)} cases, want {want}")

    single_cwes = Counter()
    decoyed = 0
    cwe798_multi = 0
    for c in cases:
        vulns = c.get("vulnerabilities", [])
        cwes = [v["cwe"] for v in vulns]
        if c["category"] != "clean" and c.get("decoys"):
            decoyed += 1
        if c["category"] == "single":
            if len(vulns) != 1 or cwes[0] not in PRIMARY_CWES:
                problems.append(f"{c['case_id']}: single must have exactly one primary-CWE vuln")
            else:
                single_cwes[cwes[0]] += 1
        elif c["category"] == "multi":
            if not 2 <= len(vulns) <= 3:
                problems.append(f"{c['case_id']}: multi must have 2-3 vulns, has {len(vulns)}")
            if not any(cwe in PRIMARY_CWES for cwe in cwes):
                problems.append(f"{c['case_id']}: multi needs at least one primary CWE")
            if len(set(cwes)) != len(cwes):
                problems.append(f"{c['case_id']}: multi repeats a CWE")
            if cwes.count("CWE-798") > 1:
                problems.append(f"{c['case_id']}: more than one CWE-798")
            cwe798_multi += "CWE-798" in cwes
        elif c["category"] == "clean":
            if vulns:
                problems.append(f"{c['case_id']}: clean case has vulns")
            if len(c.get("decoys", [])) < 2:
                problems.append(f"{c['case_id']}: clean case needs 2+ decoys")
        unknown = set(cwes) - PRIMARY_CWES - SECONDARY_CWES
        if unknown:
            problems.append(f"{c['case_id']}: unknown CWE(s) {sorted(unknown)}")

    for cwe in sorted(PRIMARY_CWES):
        if single_cwes[cwe] != 4:
            problems.append(f"singles with {cwe}: {single_cwes[cwe]}, want 4")
    if not 4 <= cwe798_multi <= 6:
        problems.append(f"multi cases with CWE-798: {cwe798_multi}, want about 5")
    if decoyed < 8:
        problems.append(f"single/multi cases with a decoy: {decoyed}, want 8+")
    return problems


# --- main ----------------------------------------------------------------------

COLUMNS = ["files", "static", "import", "functional", "security", "ground_truth"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("cases", nargs="*", help="only validate these case ids")
    parser.add_argument("--partial", action="store_true",
                        help="skip the dataset composition check")
    args = parser.parse_args(argv)

    data = json.loads((ROOT / "ground_truth.json").read_text())
    cases = data["cases"]
    failures = 0

    ids = [c["case_id"] for c in cases]
    dirs = sorted(p.name for p in ROOT.glob("case_*") if p.is_dir())
    orphan = sorted(set(dirs) - set(ids))
    dupes = [i for i, n in Counter(ids).items() if n > 1]

    selected = [c for c in cases if not args.cases or c["case_id"] in args.cases]

    width = max([len(c["case_id"]) for c in selected] + [10])
    print(f"{'case':<{width}}  " + "  ".join(f"{c:<12}" for c in COLUMNS) + "  result")
    print("-" * (width + 14 * len(COLUMNS) + 8))
    details = []
    for case in selected:
        row, problems = validate_case(case)
        result = "FAIL" if problems else "PASS"
        failures += bool(problems)
        cells = "  ".join(f"{row.get(c, '-'):<12}" for c in COLUMNS)
        print(f"{case['case_id']:<{width}}  {cells}  {result}")
        if problems:
            details.append((case["case_id"], problems))

    for case_id, problems in details:
        print(f"\n[{case_id}]")
        for p in problems:
            print(f"  - {p}")

    dataset_problems = []
    if orphan:
        dataset_problems.append(f"case folders missing from ground_truth.json: {orphan}")
    if dupes:
        dataset_problems.append(f"duplicate case ids: {dupes}")
    if not args.partial and not args.cases:
        dataset_problems += check_composition(cases)

    print("\nDataset checks" + (" (composition skipped)" if args.partial or args.cases else ""))
    for p in dataset_problems:
        print(f"  - FAIL: {p}")
    if not dataset_problems:
        print("  PASS")

    n_vulns = sum(len(c.get("vulnerabilities", [])) for c in selected)
    n_decoys = sum(len(c.get("decoys", [])) for c in selected)
    print(f"\nSummary: {len(selected) - failures}/{len(selected)} cases pass; "
          f"{n_vulns} vulnerabilities, {n_decoys} decoys; "
          f"{len(dataset_problems)} dataset-level problem(s)")
    return 1 if failures or dataset_problems else 0


if __name__ == "__main__":
    sys.exit(main())
