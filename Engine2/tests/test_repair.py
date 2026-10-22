"""Stage 3 tests. Owner: ____

Uses FakeLLM only -- no API key, no bandit, no other stage.
"""

import pytest

from config import CONFIG, Config
from llm import OfflineLLM
from models import Explanation, Finding, TriagedFinding
from stages.repair import (build_user_message, extract_fixed_code, extract_risk,
                           extract_section, repair)
from fakes import FIXED_APP, FakeLLM, make_case


def report(risk="Low", code=FIXED_APP, section_e="NONE"):
    body = f"```python\n{code}```" if code else "NO FIX POSSIBLE"
    return (f"A. FINDINGS\n1. CWE-89 at line 20\n\n"
            f"B. EXPLANATIONS\nThe name is now a bound parameter.\n\n"
            f"C. COMPATIBILITY RISK\n{risk} -- same return shape and exceptions.\n\n"
            f"D. FIXED CODE\n{body}\n\n"
            f"E. PROPOSE TO HUMAN\n{section_e}")


@pytest.fixture
def confirmed():
    return [TriagedFinding(
        finding=Finding(case_id="case_99_fake", cwe="CWE-89", line_start=20,
                        line_end=20, rule_id="B608"),
        verdict="real",
        explanation=Explanation(what="f-stringed name", why="table disclosure",
                                how_exploited="x' OR '1'='1"),
    )]


# --- A-E parsing (same format as v0) -----------------------------------------

def test_extracts_the_fixed_code_block():
    assert extract_fixed_code(report()) == FIXED_APP


@pytest.mark.parametrize("risk", ["Low", "Medium", "High"])
def test_extracts_each_risk_level(risk):
    assert extract_risk(report(risk=risk)) == risk


def test_missing_risk_section_defaults_to_high():
    """Fail safe: an unreadable risk must never read as Low."""
    assert extract_risk("A. FINDINGS\nnothing here") == "High"


def test_no_fix_possible_yields_no_code():
    assert extract_fixed_code(report(code=None)) is None


def test_no_changes_yields_no_code():
    assert extract_fixed_code(report().replace(f"```python\n{FIXED_APP}```", "NO CHANGES")) is None


def test_unfenced_code_is_still_accepted():
    raw = report().replace(f"```python\n{FIXED_APP}```", FIXED_APP)
    assert extract_fixed_code(raw).strip().startswith('"""Tiny app')


def test_sections_do_not_bleed_into_each_other():
    assert "COMPATIBILITY" not in extract_section(report(), "B. EXPLANATIONS",
                                                  "C. COMPATIBILITY RISK")


# --- the stage ---------------------------------------------------------------

def test_repair_returns_a_fix(tmp_path, confirmed):
    case = make_case(tmp_path)
    fix = repair(case, confirmed, FakeLLM([report()]), CONFIG)
    assert fix.has_code and fix.risk == "Low"
    assert fix.addressed_cwes == ["CWE-89"]
    assert fix.no_fix_possible is False
    assert fix.attempt == 1


def test_no_fix_possible_escape_hatch(tmp_path, confirmed):
    case = make_case(tmp_path)
    fix = repair(case, confirmed, FakeLLM([report(code=None)]), CONFIG)
    assert fix.no_fix_possible is True and not fix.has_code


def test_api_failure_is_not_a_fix(tmp_path, confirmed):
    case = make_case(tmp_path)
    fix = repair(case, confirmed, FakeLLM([RuntimeError("timeout")]), CONFIG)
    assert not fix.has_code and fix.risk == "High" and "failed" in fix.notes


def test_feedback_from_a_failed_attempt_reaches_the_prompt(tmp_path, confirmed):
    case = make_case(tmp_path)
    llm = FakeLLM([report()])
    repair(case, confirmed, llm, CONFIG,
           feedback="test_find_missing passed before and fails now", attempt=2)
    user = llm.last_user_message
    assert "ATTEMPT 2" in user
    assert "test_find_missing passed before and fails now" in user


def test_the_confirmed_findings_and_their_explanations_reach_the_prompt(tmp_path, confirmed):
    case = make_case(tmp_path)
    llm = FakeLLM([report()])
    repair(case, confirmed, llm, CONFIG)
    user = llm.last_user_message
    assert "CWE-89" in user and "f-stringed name" in user
    assert "untrusted data" in user and "BEGIN-" in user


def test_nothing_confirmed_means_no_call(tmp_path):
    llm = FakeLLM([report()])
    fix = repair(make_case(tmp_path), [], llm, CONFIG)
    assert not fix.has_code and llm.calls == 0


def test_offline_returns_the_code_unchanged_at_high_risk(tmp_path, confirmed):
    case = make_case(tmp_path)
    llm = OfflineLLM(Config(offline=True))
    fix = repair(case, confirmed, llm, CONFIG)
    assert fix.fixed_code == case.code
    assert fix.risk == "High"          # so stage 5 can never auto-apply it
    assert llm.calls == 0
