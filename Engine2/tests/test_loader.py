"""Tests for dataset_loader.py (the one file that knows the dataset format)."""

import json

from dataset_loader import load_case, load_cases, missing_functional_tests
from fakes import VULNERABLE_APP, make_case

GROUND_TRUTH = {
    "dataset_version": "test",
    "cases": [{
        "case_id": "case_99_fake",
        "category": "multi",
        "context": "a fake case",
        "vulnerabilities": [{
            "vuln_id": "case_99-v1", "cwe": "CWE-89", "function": "find",
            "line_start": 20, "line_end": 20, "subtlety": "obvious",
            "expected_fix_risk": "Low", "description": "f-stringed name",
            "security_test": "test_security.py::test_v1_not_injectable",
            "related_lines": [{"function": "helper", "line_start": 20, "line_end": 22}],
        }],
        "decoys": [{
            "decoy_id": "case_99-d1", "looks_like": "CWE-89", "function": "connect",
            "line_start": 15, "line_end": 15, "why_safe": "constant table name",
        }],
    }],
}


def _dataset(tmp_path):
    make_case(tmp_path)
    (tmp_path / "ground_truth.json").write_text(json.dumps(GROUND_TRUTH), encoding="utf-8")
    return tmp_path


def test_loads_case_with_annotations(tmp_path):
    cases = load_cases(_dataset(tmp_path))
    assert len(cases) == 1
    case = cases[0]
    assert case.case_id == "case_99_fake"
    assert case.category == "multi"
    assert case.code == VULNERABLE_APP
    assert [v.cwe for v in case.vulns] == ["CWE-89"]
    assert case.has_functional_tests and case.has_security_tests


def test_decoy_looks_like_becomes_its_cwe(tmp_path):
    case = load_cases(_dataset(tmp_path))[0]
    assert len(case.decoys) == 1
    assert case.decoys[0].cwe == "CWE-89"
    assert case.decoys[0].is_decoy is True


def test_related_lines_are_extra_match_spans(tmp_path):
    vuln = load_cases(_dataset(tmp_path))[0].vulns[0]
    assert vuln.related_lines == [(20, 22)]
    assert vuln.spans(tolerance=3) == [(17, 23), (17, 25)]
    assert vuln.spans(tolerance=0) == [(20, 20), (20, 22)]


def test_span_never_goes_below_line_one(tmp_path):
    case = load_cases(_dataset(tmp_path))[0]
    case.vulns[0].line_start = 1
    assert case.vulns[0].spans(tolerance=3)[0][0] == 1


def test_case_without_ground_truth_entry_loads_empty(tmp_path):
    make_case(tmp_path)
    case = load_case(tmp_path / "case_99_fake")
    assert case.vulns == [] and case.decoys == []


def test_missing_functional_tests_is_reported(tmp_path):
    case = make_case(tmp_path, with_functional=False)
    assert missing_functional_tests([case]) == [case.case_id]
