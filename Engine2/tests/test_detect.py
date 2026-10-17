"""Stage 1 tests. Owner: ____"""

import pytest

from config import CONFIG, Config
from stages.detect import _ast_findings, _cwe_of, _dedupe, detect, detect_code
from stages.detect import _finding_from_bandit
from fakes import VULNERABLE_APP, make_case

AST_CFG = Config(use_ast_supplement=True)


# --- CWE mapping and the alias table (pure, no bandit needed) ----------------

@pytest.mark.parametrize("raw,expected", [
    ("CWE-89", "CWE-89"),
    ("CWE-259", "CWE-798"),      # hard-coded password -> hard-coded credentials
    ("CWE-328", "CWE-327"),      # weak hash           -> broken crypto
    ("CWE-916", "CWE-327"),
    ("CWE-77", "CWE-78"),
    ("89", "CWE-89"),            # bare number
    ("CWE-502", None),           # not one of ours: dropped
    (None, None),
])
def test_resolved_cwe(raw, expected):
    assert CONFIG.resolved_cwe(raw) == expected


def test_cwe_read_from_bandit_json():
    assert _cwe_of({"issue_cwe": {"id": 89}}) == "CWE-89"
    assert _cwe_of({}) is None


def test_finding_built_from_bandit_result():
    finding = _finding_from_bandit({
        "issue_cwe": {"id": 259}, "line_range": [12, 13], "line_number": 12,
        "test_id": "B105", "issue_severity": "LOW", "issue_confidence": "MEDIUM",
        "issue_text": "Possible hardcoded password", "code": "PASSWORD = 'hunter2'",
    }, "case_x", CONFIG)
    assert (finding.cwe, finding.line_start, finding.line_end) == ("CWE-798", 12, 13)
    assert finding.rule_id == "B105" and finding.detector == "bandit"


def test_non_target_cwe_is_dropped():
    assert _finding_from_bandit({"issue_cwe": {"id": 502}, "line_number": 3}, "c", CONFIG) is None


def test_dedupe_prefers_bandit_over_ast():
    from models import Finding
    bandit = Finding(case_id="c", cwe="CWE-89", line_start=5, line_end=5, detector="bandit")
    ast_dup = Finding(case_id="c", cwe="CWE-89", line_start=5, line_end=5, detector="ast")
    assert [f.detector for f in _dedupe([ast_dup, bandit])] == ["bandit"]


# --- the AST supplement (pure, no bandit needed) -----------------------------

def test_ast_supplement_finds_the_cwe_22_bandit_has_no_rule_for():
    code = ("import os\n"
            "def read(name):\n"
            "    path = os.path.join('/var/log', name)\n"
            "    with open(path) as handle:\n"
            "        return handle.read()\n")
    assert "CWE-22" in {f.cwe for f in _ast_findings(code, "c", AST_CFG)}


def test_ast_supplement_survives_a_syntax_error():
    assert _ast_findings("def broken(:\n", "c", AST_CFG) == []


def test_ast_supplement_finds_secret_literal_and_weak_hash():
    code = "import hashlib\nAPI_KEY = 'sk-live-abc'\nd = hashlib.md5(b'x').hexdigest()\n"
    cwes = {f.cwe for f in _ast_findings(code, "c", AST_CFG)}
    assert {"CWE-798", "CWE-327"} <= cwes


# --- bandit itself -----------------------------------------------------------

def test_detect_reports_sql_injection(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    findings = detect(case, CONFIG)
    assert findings, "bandit should report the f-stringed query"
    assert "CWE-89" in {f.cwe for f in findings}
    assert all(f.case_id == case.case_id for f in findings)


def test_detect_over_flags_on_purpose(tmp_path):
    """The point of stage 1: it reports more than the one real flaw."""
    case = make_case(tmp_path, code=VULNERABLE_APP)
    assert len(detect(case, CONFIG)) > len(case.vulns)


def test_detect_code_matches_detect_on_the_same_source(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    by_file = [(f.cwe, f.line_start) for f in detect(case, CONFIG)]
    by_string = [(f.cwe, f.line_start) for f in detect_code(case.code, case.case_id, CONFIG)]
    assert by_file == by_string


def test_detect_is_quiet_on_harmless_code(tmp_path):
    case = make_case(tmp_path, code="def add(a, b):\n    return a + b\n")
    assert detect(case, CONFIG) == []
