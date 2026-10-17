"""Stage 2 tests. Owner: ____

Uses FakeLLM only -- no API key, no bandit, no other stage.
"""

import pytest

from config import CONFIG, Config
from llm import OfflineLLM
from models import Finding
from stages.triage import parse_reply, triage
from fakes import FakeLLM, make_case

REAL = ("VERDICT: VULNERABLE\n"
        "WHAT: the name is f-stringed straight into the SELECT.\n"
        "WHY: an attacker reads the whole table.\n"
        "EXPLOIT: pass x' OR '1'='1 as the name.")

CLEARED = ("VERDICT: NOT VULNERABLE\n"
           "WHAT: only the module constant TABLE is interpolated; name is bound.\n"
           "WHY: n/a\n"
           "EXPLOIT: n/a")


@pytest.fixture
def finding():
    return Finding(case_id="case_99_fake", cwe="CWE-89", line_start=20, line_end=20,
                   rule_id="B608", message="possible SQL injection")


# --- parsing -----------------------------------------------------------------

def test_parses_a_vulnerable_verdict():
    verdict, explanation = parse_reply(REAL)
    assert verdict == "real"
    assert "f-stringed" in explanation.what
    assert explanation.why.startswith("an attacker")
    assert "OR '1'='1" in explanation.how_exploited


def test_parses_the_not_vulnerable_escape_hatch():
    verdict, explanation = parse_reply(CLEARED)
    assert verdict == "false_alarm"
    assert "module constant" in explanation.what


@pytest.mark.parametrize("reply", [
    "", "   ", "I think it's fine", "VERDICT:", "probably VULNERABLE maybe?",
])
def test_unusable_replies_give_no_verdict(reply):
    assert parse_reply(reply)[0] is None


# --- the escape hatch and the fail-safe --------------------------------------

def test_real_verdict_is_reported(tmp_path, finding):
    case = make_case(tmp_path)
    triaged = triage(case, [finding], FakeLLM([REAL]), CONFIG)
    assert [t.verdict for t in triaged] == ["real"]
    assert triaged[0].is_real


def test_false_alarm_is_dropped_from_reported(tmp_path, finding):
    case = make_case(tmp_path)
    triaged = triage(case, [finding], FakeLLM([CLEARED]), CONFIG)
    assert triaged[0].verdict == "false_alarm"
    assert not triaged[0].is_real


def test_unparseable_reply_keeps_the_finding(tmp_path, finding):
    """The contract: no usable verdict must never silently delete a finding."""
    case = make_case(tmp_path)
    triaged = triage(case, [finding], FakeLLM(["who knows"]), CONFIG)
    assert triaged[0].verdict == "real"
    assert "no usable VERDICT" in triaged[0].notes


def test_api_failure_keeps_the_finding(tmp_path, finding):
    case = make_case(tmp_path)
    triaged = triage(case, [finding], FakeLLM([RuntimeError("503 overloaded")]), CONFIG)
    assert triaged[0].verdict == "real"
    assert "triage call failed" in triaged[0].notes


# --- shape and offline -------------------------------------------------------

def test_output_is_one_per_input_in_order(tmp_path):
    case = make_case(tmp_path)
    findings = [Finding(case_id=case.case_id, cwe="CWE-89", line_start=n, line_end=n)
                for n in (15, 20)]
    triaged = triage(case, findings, FakeLLM([CLEARED, REAL]), CONFIG)
    assert [t.finding.line_start for t in triaged] == [15, 20]
    assert [t.verdict for t in triaged] == ["false_alarm", "real"]


def test_offline_keeps_everything_without_calling_the_model(tmp_path, finding):
    case = make_case(tmp_path)
    llm = OfflineLLM(Config(offline=True))
    triaged = triage(case, [finding], llm, CONFIG)
    assert triaged[0].verdict == "real"
    assert "offline" in triaged[0].notes
    assert llm.calls == 0


def test_the_file_is_sent_as_untrusted_data(tmp_path, finding):
    """The nonce-marked block from v0 must be in the prompt."""
    case = make_case(tmp_path)
    llm = FakeLLM([REAL])
    triage(case, [finding], llm, CONFIG)
    user = llm.last_user_message
    assert "untrusted data" in user and "BEGIN-" in user and "END-" in user
    assert "CWE-89" in user and "20" in user


def test_empty_findings_means_no_calls(tmp_path):
    llm = FakeLLM([REAL])
    assert triage(make_case(tmp_path), [], llm, CONFIG) == []
    assert llm.calls == 0
