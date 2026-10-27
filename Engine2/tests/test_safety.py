"""Stage 4 tests. Owner: ____

These REALLY RUN pytest in a subprocess on a temp copy of a hand-made case, so
they are the slowest group. They never call a model: that is the whole point of
the stage.
"""

import pytest

from config import CONFIG, Config
from models import Fix, TestRun
from stages.safety import verify
from fakes import (BROKEN_APP, FIXED_APP, SYNTAX_ERROR_APP, VULNERABLE_APP,
                   make_case)


def fix_for(case, code, risk="Low", cwes=("CWE-89",), attempt=1):
    return Fix(case_id=case.case_id, attempt=attempt, fixed_code=code,
               risk=risk, addressed_cwes=list(cwes))


# --- the good path -----------------------------------------------------------

def test_a_correct_fix_passes_everything(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    result = verify(case, fix_for(case, FIXED_APP), CONFIG)
    assert result.applied and result.syntax_ok
    assert result.functional_baseline.passed
    assert result.functional_after.passed
    assert result.regressions == []
    assert result.decoy_breaks == []
    assert result.security_verdict is True     # test_v1 now passes
    assert result.vuln_gone is True
    assert result.ok is True


def test_the_original_code_is_not_a_fix(tmp_path):
    """Handing the vulnerable file back must not pass the safety net."""
    case = make_case(tmp_path, code=VULNERABLE_APP)
    result = verify(case, fix_for(case, VULNERABLE_APP), CONFIG)
    assert result.functional_after.passed       # it still works, of course
    assert result.security_verdict is False     # but test_v1 still fails
    assert result.vuln_gone is False
    assert result.ok is False


# --- regressions: "passed before, fails after" -------------------------------

def test_a_regression_is_detected(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    result = verify(case, fix_for(case, BROKEN_APP), CONFIG)
    assert result.functional_baseline.passed
    assert not result.functional_after.passed
    assert "test_find_existing" in result.regressions
    assert result.tests_pass is False and result.ok is False


def test_a_test_that_already_failed_is_not_a_regression(tmp_path):
    """The baseline exists for this: a broken case is not a broken fix."""
    case = make_case(tmp_path, code=BROKEN_APP)      # baseline is already red
    result = verify(case, fix_for(case, BROKEN_APP), CONFIG)
    assert not result.functional_baseline.passed
    assert result.regressions == []                  # nothing was broken BY the fix


def test_regression_feedback_names_the_failing_test(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    result = verify(case, fix_for(case, BROKEN_APP), CONFIG)
    assert "test_find_existing" in result.feedback_for_repair
    assert "PASSED on the original" in result.feedback_for_repair


# --- breaking safe code (the decoy half of the security oracle) --------------

def test_breaking_a_previously_safe_test_is_caught(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    # "fixes" the decoy by making count() always return 0: test_d1 breaks.
    sabotage = FIXED_APP.replace("return conn.execute(sql, (name,)).fetchone()[0]",
                                 "return 0")
    result = verify(case, fix_for(case, sabotage), CONFIG)
    assert result.decoy_breaks == ["test_d1_count_is_safe"]
    assert result.tests_pass is False and result.ok is False
    assert "already SAFE" in result.feedback_for_repair


# --- bad input ---------------------------------------------------------------

def test_a_syntax_error_short_circuits_before_any_test_runs(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    result = verify(case, fix_for(case, SYNTAX_ERROR_APP), CONFIG)
    assert result.syntax_ok is False
    assert result.functional_baseline.ran is False    # never got that far
    assert "SyntaxError" in result.feedback_for_repair
    assert result.ok is False


def test_no_code_means_nothing_to_test(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    result = verify(case, fix_for(case, None), CONFIG)
    assert result.applied is False and result.ok is False
    assert "no fixed code" in result.feedback_for_repair


def test_a_case_without_functional_tests_cannot_show_a_regression(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP, with_functional=False)
    result = verify(case, fix_for(case, FIXED_APP), CONFIG)
    assert result.functional_baseline.ran is False
    assert result.regressions == []
    assert result.tests_pass is False        # no evidence is not a pass
    assert result.ok is False


def test_a_case_without_security_tests_falls_back_to_the_rescan(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP, with_security=False)
    result = verify(case, fix_for(case, FIXED_APP), CONFIG)
    assert result.security_after is None
    assert result.security_verdict is None
    assert result.vuln_gone == result.rescan_clear


def test_the_original_case_folder_is_never_modified(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    verify(case, fix_for(case, FIXED_APP), CONFIG)
    assert case.app_path.read_text(encoding="utf-8") == VULNERABLE_APP


def test_an_infinite_loop_is_killed_by_the_timeout(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    spin = FIXED_APP + "\n\nwhile True:\n    pass\n"
    result = verify(case, fix_for(case, spin), Config(test_timeout=5))
    assert result.functional_after.timed_out is True
    assert result.ok is False


# --- the baseline runs once per case -----------------------------------------

@pytest.fixture
def functional_runs(monkeypatch):
    """Empty baseline store, and the app.py of every test_functional.py run, in order."""
    from stages import safety
    monkeypatch.setattr(safety, "_BASELINES", {})
    runs = []
    real_run_pytest = safety._run_pytest

    def recording(workdir, test_file, cfg):
        if test_file == "test_functional.py":
            runs.append((workdir / "app.py").read_text(encoding="utf-8"))
        return real_run_pytest(workdir, test_file, cfg)

    monkeypatch.setattr(safety, "_run_pytest", recording)
    return runs


def test_the_baseline_is_reused_by_later_attempts(tmp_path, functional_runs):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    first = verify(case, fix_for(case, BROKEN_APP, attempt=1), CONFIG)
    second = verify(case, fix_for(case, FIXED_APP, attempt=2), CONFIG)
    # attempt 1: baseline + fix; attempt 2: fix only
    assert functional_runs == [VULNERABLE_APP, BROKEN_APP, FIXED_APP]
    assert second.functional_baseline.per_test == first.functional_baseline.per_test
    assert first.regressions and second.regressions == []


def test_same_case_id_with_different_code_runs_its_own_baseline(tmp_path, functional_runs):
    case = make_case(tmp_path / "a", code=VULNERABLE_APP)
    other = make_case(tmp_path / "b", code=BROKEN_APP)     # same case_id
    verify(case, fix_for(case, FIXED_APP), CONFIG)
    result = verify(other, fix_for(other, BROKEN_APP), CONFIG)
    assert functional_runs == [VULNERABLE_APP, FIXED_APP, BROKEN_APP, BROKEN_APP]
    assert not result.functional_baseline.passed


def test_a_timed_out_baseline_is_not_reused(tmp_path, monkeypatch, functional_runs):
    from stages import safety
    recording = safety._run_pytest

    def baseline_times_out(workdir, test_file, cfg):
        result = recording(workdir, test_file, cfg)
        if (workdir / "app.py").read_text(encoding="utf-8") == VULNERABLE_APP:
            return TestRun(ran=True, timed_out=True, returncode=-9)
        return result

    monkeypatch.setattr(safety, "_run_pytest", baseline_times_out)
    case = make_case(tmp_path, code=VULNERABLE_APP)
    verify(case, fix_for(case, FIXED_APP, attempt=1), CONFIG)
    verify(case, fix_for(case, FIXED_APP, attempt=2), CONFIG)
    assert functional_runs == [VULNERABLE_APP, FIXED_APP, VULNERABLE_APP, FIXED_APP]
    assert safety._BASELINES == {}


# --- the environment handed to untrusted code --------------------------------

def test_secret_env_vars_are_stripped_from_the_test_subprocess(tmp_path, monkeypatch):
    """The API key must not be readable by the code stage 4 runs."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-leak")
    monkeypatch.setenv("MY_DEPLOY_TOKEN", "also-secret")
    case = make_case(tmp_path, code=VULNERABLE_APP)
    # a functional test that fails loudly if it can see either variable
    (case.path / "test_functional.py").write_text(
        "import os\n\n\n"
        "def test_no_secrets_visible(mod):\n"
        "    assert 'ANTHROPIC_API_KEY' not in os.environ\n"
        "    assert 'MY_DEPLOY_TOKEN' not in os.environ\n"
        "    assert os.environ.get('PATH'), 'PATH should survive'\n",
        encoding="utf-8")
    result = verify(case, fix_for(case, FIXED_APP), CONFIG)
    assert result.functional_after.passed, result.functional_after.output


def test_the_stripper_keeps_ordinary_variables():
    from stages.safety import _subprocess_env
    env = _subprocess_env(TARGET_MODULE="app")
    assert env["TARGET_MODULE"] == "app"
    assert "PATH" in env
    assert not [k for k in env if "SECRET" in k.upper() or "TOKEN" in k.upper()]
