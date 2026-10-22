"""
Dataset loading: ALL knowledge of the dataset's on-disk format lives here.
=========================================================================

Job
---
Turn `dataset/` into `list[Case]`. No other file may read ground_truth.json or
guess a case's layout. If the dataset format changes, only this file changes.

Format it expects (dataset/README.md, dataset/PLAN.md):
    <cases_dir>/ground_truth.json       {"cases": [{case_id, category, context,
                                          vulnerabilities[], decoys[]}, ...]}
    <cases_dir>/case_NN_<name>/app.py              <- the only file a fixer sees
                              reference_fix.py     <- answer key, never shown
                              test_functional.py   <- behaviour oracle
                              test_security.py     <- security oracle
                              conftest.py          <- mod / secret_env / empty_env

Contract
--------
    load_cases(cases_dir, cfg=CONFIG) -> list[Case]
    load_case(case_dir, annotations=None, cfg=CONFIG) -> Case
    missing_functional_tests(cases) -> list[str]

Owner: ____ (shared file -- changes need a reviewed PR)

Known gaps
----------
- Reads the dataset read-only and ignores `reference_fix.py` entirely. Comparing
  a candidate fix to the reference is not implemented (the dataset README warns
  the reference is one correct fix, not the only one).
- A case folder with no entry in ground_truth.json loads with no annotations, so
  it scores as all-false-positive rather than being skipped loudly.
- Only `app.py` is loaded. Multi-file cases are not supported.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from config import CONFIG, Config
from models import Annotation, Case

GROUND_TRUTH = "ground_truth.json"
APP_FILE = "app.py"
FUNCTIONAL_TESTS = "test_functional.py"
SECURITY_TESTS = "test_security.py"


def _related(raw: dict) -> list[tuple[int, int]]:
    out = []
    for item in raw.get("related_lines") or []:
        start, end = item.get("line_start"), item.get("line_end")
        if start is not None and end is not None:
            out.append((int(start), int(end)))
    return out


def _vuln(raw: dict) -> Annotation:
    return Annotation(
        ann_id=raw.get("vuln_id", ""),
        cwe=str(raw.get("cwe", "")).upper(),
        line_start=int(raw["line_start"]),
        line_end=int(raw["line_end"]),
        is_decoy=False,
        function=raw.get("function", ""),
        description=raw.get("description", ""),
        subtlety=raw.get("subtlety", ""),
        expected_fix_risk=raw.get("expected_fix_risk", ""),
        regression_note=raw.get("regression_note", ""),
        security_test=raw.get("security_test", ""),
        related_lines=_related(raw),
    )


def _decoy(raw: dict) -> Annotation:
    """A decoy is a safe look-alike: its `looks_like` CWE is what a scanner may cry."""
    return Annotation(
        ann_id=raw.get("decoy_id", ""),
        cwe=str(raw.get("looks_like", "")).upper(),
        line_start=int(raw["line_start"]),
        line_end=int(raw["line_end"]),
        is_decoy=True,
        function=raw.get("function", ""),
        description=raw.get("why_safe", ""),
        security_test=raw.get("security_test", ""),
        related_lines=_related(raw),
    )


def load_annotations(cases_dir: Path | str) -> dict[str, dict]:
    """case_id -> its ground_truth.json entry. Empty dict when the file is absent."""
    path = Path(cases_dir) / GROUND_TRUTH
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {entry["case_id"]: entry for entry in data.get("cases", [])}


def load_case(case_dir: Path | str,
              annotations: Optional[dict] = None,
              cfg: Config = CONFIG) -> Case:
    """Load one case folder. `annotations` is its ground_truth.json entry, if any."""
    case_dir = Path(case_dir)
    app_path = case_dir / APP_FILE
    entry = annotations or {}
    return Case(
        case_id=entry.get("case_id", case_dir.name),
        path=case_dir,
        app_path=app_path,
        code=app_path.read_text(encoding="utf-8") if app_path.is_file() else "",
        category=entry.get("category", ""),
        context=entry.get("context", ""),
        vulns=[_vuln(v) for v in entry.get("vulnerabilities", [])],
        decoys=[_decoy(d) for d in entry.get("decoys", [])],
        has_functional_tests=(case_dir / FUNCTIONAL_TESTS).is_file(),
        has_security_tests=(case_dir / SECURITY_TESTS).is_file(),
    )


def load_cases(cases_dir: Path | str, cfg: Config = CONFIG) -> list[Case]:
    """Every `case_*` folder holding an app.py, sorted by folder name."""
    cases_dir = Path(cases_dir)
    if not cases_dir.is_dir():
        raise FileNotFoundError(f"No such cases directory: {cases_dir}")
    annotations = load_annotations(cases_dir)
    cases = []
    for folder in sorted(p for p in cases_dir.iterdir() if p.is_dir()):
        if not folder.name.startswith("case") or not (folder / APP_FILE).is_file():
            continue
        cases.append(load_case(folder, annotations.get(folder.name), cfg))
    return cases


def missing_functional_tests(cases: list[Case]) -> list[str]:
    """Case ids with no test_functional.py. Stage 4 cannot score regressions for these."""
    return [c.case_id for c in cases if not c.has_functional_tests]
