"""Orchestrator tests: the retry loop and the offline run. Owner: ____ (shared)"""

from config import Config
from llm import OfflineLLM
from models import Finding
from orchestrator import run_case
from stages.repair import NO_FIX
from fakes import BROKEN_APP, FIXED_APP, VULNERABLE_APP, FakeLLM, make_case

REAL = ("VERDICT: VULNERABLE\nWHAT: f-stringed name.\nWHY: disclosure.\n"
        "EXPLOIT: x' OR '1'='1")
CLEARED = "VERDICT: NOT VULNERABLE\nWHAT: constant table.\nWHY: n/a\nEXPLOIT: n/a"


def fix_report(code, risk="Low"):
    body = f"```python\n{code}```" if code else NO_FIX
    return (f"A. FINDINGS\n1. CWE-89 line 20\n\nB. EXPLANATIONS\nbound it\n\n"
            f"C. COMPATIBILITY RISK\n{risk}\n\nD. FIXED CODE\n{body}\n\n"
            f"E. PROPOSE TO HUMAN\nNONE")


def test_a_good_fix_is_auto_applied_in_one_attempt(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    # bandit reports 2 CWE-89 here, so triage is called twice before repair.
    llm = FakeLLM(lambda system, user: REAL if "FINDING TO JUDGE" in user
                  else fix_report(FIXED_APP))
    result = run_case(case, llm, Config())
    assert result.decision.action == "auto_apply"
    assert len(result.fixes) == 1
    assert result.final_safety.ok


def test_a_regression_triggers_a_retry_with_feedback(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    sent: list[str] = []

    def reply(system, user):
        if "FINDING TO JUDGE" in user:
            return REAL
        sent.append(user)
        # first repair attempt breaks a test, second one is correct
        return fix_report(BROKEN_APP if len(sent) == 1 else FIXED_APP)

    result = run_case(case, FakeLLM(reply), Config())
    assert len(result.fixes) == 2
    assert "ATTEMPT 2" in sent[1]
    assert "test_find_existing" in sent[1]          # stage 4's output, fed back
    assert result.decision.action == "auto_apply"


def test_the_retry_loop_stops_at_the_limit(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    llm = FakeLLM(lambda system, user: REAL if "FINDING TO JUDGE" in user
                  else fix_report(BROKEN_APP))
    result = run_case(case, llm, Config(max_repair_attempts=2))
    assert len(result.fixes) == 2
    assert result.decision.action == "propose_to_human"


def test_everything_cleared_in_triage_means_no_repair(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    llm = FakeLLM([CLEARED])
    result = run_case(case, llm, Config())
    assert result.reported == []
    assert result.fixes == []
    assert result.decision.action == "no_action"


def test_no_fix_possible_stops_the_loop(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    llm = FakeLLM(lambda system, user: REAL if "FINDING TO JUDGE" in user
                  else fix_report(None))
    result = run_case(case, llm, Config())
    assert len(result.fixes) == 1                   # no point retrying
    assert result.decision.action == "propose_to_human"


def test_the_offline_run_completes_without_an_api_key(tmp_path):
    """The guard for `python run.py <dataset> --offline`: it must stay green."""
    case = make_case(tmp_path, code=VULNERABLE_APP)
    cfg = Config(offline=True)
    result = run_case(case, OfflineLLM(cfg), cfg)
    assert result.error == ""
    assert result.reported, "offline triage keeps every finding"
    assert len(result.fixes) == 1                   # no retry: the answer cannot change
    assert result.fixes[0].risk == "High"
    assert result.decision.action == "propose_to_human"


def test_a_stage_crash_is_recorded_and_does_not_escape(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    result = run_case(case, FakeLLM([RuntimeError("boom")]), Config(max_repair_attempts=1))
    # triage fails safe (findings kept), repair records the failure, no exception
    assert result.reported
    assert not result.fixes[0].has_code
    assert result.decision.action == "propose_to_human"


# --- the preflight -----------------------------------------------------------

def test_preflight_rejects_a_broken_credential():
    """A run whose calls all fail must not produce a report that looks real."""
    import pytest

    from llm import PreflightError, preflight
    with pytest.raises(PreflightError) as caught:
        preflight(FakeLLM([RuntimeError("Error code: 401 - invalid x-api-key")]))
    message = str(caught.value)
    assert "NOT run" in message
    assert "sk-ant-api03-" in message      # tells the reader what a real key looks like
    assert "--offline" in message          # and the way out that needs no key


def test_preflight_passes_a_working_credential():
    from llm import preflight
    llm = FakeLLM(["ok"])
    preflight(llm)                          # must not raise
    assert llm.calls == 1


def test_preflight_is_free_in_offline_mode():
    from llm import preflight
    llm = OfflineLLM(Config(offline=True))
    preflight(llm)
    assert llm.calls == 0
