"""Stage 4 tests. Owner: ____

These REALLY RUN pytest in a subprocess on a temp copy of a hand-made case, so
they are the slowest group. They never call a model: that is the whole point of
the stage.
"""

import dataclasses
import subprocess
import sys
from pathlib import Path

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
    result = verify(case, fix_for(case, spin), Config(test_timeout=5, sandbox_timeout=5))
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


# --- the Docker sandbox ------------------------------------------------------
# These need no Docker: they check the docker command, the copy, and what
# happens when Docker is missing. The last one runs a real container and is
# skipped when Docker or the image is not available.

def _no_docker(monkeypatch):
    from stages import safety
    monkeypatch.setattr(safety, "_docker_problem", lambda cfg: "Docker is not installed")
    monkeypatch.setattr(safety, "_warned_unisolated", False)


def test_the_docker_command_carries_every_isolation_rule(tmp_path):
    from stages.safety import _docker_command
    cmd = _docker_command("aieval-x", tmp_path / "case", "test_functional.py", CONFIG)
    line = " ".join(cmd)
    assert "--network none" in line
    assert "--memory 512m" in line and "--memory-swap 512m" in line
    assert "--cpus 1" in line and "--pids-limit 64" in line
    assert "--read-only" in line and "/tmp:rw,size=64m" in line
    assert "--user 1000:1000" in line and "--cap-drop ALL" in line
    # one mount, read-only: nothing in the container can write to the host
    mounts = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "-v"]
    assert mounts == [f"{tmp_path / 'case'}:/case:ro"]
    # leftover processes are killed before the report is read
    assert "kill -9 -1" in cmd[-1]
    passed_env = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "-e"]
    assert sorted(v.split("=")[0] for v in passed_env) == \
        ["HOME", "PYTHONDONTWRITEBYTECODE", "TARGET_MODULE"]


def test_only_python_files_reach_the_test_run(tmp_path, monkeypatch):
    from stages import safety
    case = make_case(tmp_path, code=VULNERABLE_APP)
    (case.path / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-x", encoding="utf-8")
    (case.path / "secrets.json").write_text("{}", encoding="utf-8")
    (case.path / ".git").mkdir()
    (case.path / "pkg").mkdir()
    (case.path / "pkg" / "helper.py").write_text("X = 1\n", encoding="utf-8")
    (case.path / "pkg" / "data.csv").write_text("a,b\n", encoding="utf-8")
    seen = []

    def inspect(workdir, test_file, cfg):
        seen.append(sorted(p.relative_to(workdir).as_posix()
                           for p in workdir.rglob("*") if p.is_file()))
        return TestRun(ran=True, passed=True)

    monkeypatch.setattr(safety, "_run_pytest", inspect)
    verify(case, fix_for(case, FIXED_APP), CONFIG)
    assert seen[0] == ["app.py", "conftest.py", "pkg/helper.py",
                       "test_functional.py", "test_security.py"]


def test_a_symlink_is_never_followed_into_the_copy(tmp_path):
    from stages.safety import _allowlist
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE KEY", encoding="utf-8")
    folder = tmp_path / "case"
    folder.mkdir()
    try:
        (folder / "app_data.py").symlink_to(secret)
    except OSError:
        pytest.skip("this machine does not allow creating symlinks")
    assert _allowlist(str(folder), ["app_data.py"]) == {"app_data.py"}


def test_without_docker_and_without_opt_in_stage_4_refuses(tmp_path, monkeypatch):
    from stages.safety import SandboxUnavailable, sandbox_preflight
    _no_docker(monkeypatch)
    cfg = dataclasses.replace(CONFIG, allow_unisolated=False)
    case = make_case(tmp_path, code=VULNERABLE_APP)
    with pytest.raises(SandboxUnavailable, match="--allow-unisolated"):
        sandbox_preflight(cfg)
    with pytest.raises(SandboxUnavailable):
        verify(case, fix_for(case, FIXED_APP), cfg)


def test_opting_in_runs_unisolated_and_records_it(tmp_path, monkeypatch, capsys):
    from stages.safety import sandbox_preflight
    _no_docker(monkeypatch)
    cfg = dataclasses.replace(CONFIG, allow_unisolated=True)
    case = make_case(tmp_path, code=VULNERABLE_APP)
    assert sandbox_preflight(cfg) == "UNISOLATED"
    first = verify(case, fix_for(case, FIXED_APP), cfg)
    verify(case, fix_for(case, FIXED_APP, attempt=2), cfg)
    assert first.functional_after.passed
    assert first.functional_after.isolated is False
    assert capsys.readouterr().err.count("UNISOLATED") == 1   # warned once, not per run


def test_with_docker_ready_the_tests_go_to_the_container(tmp_path, monkeypatch):
    from stages import safety
    monkeypatch.setattr(safety, "_docker_problem", lambda cfg: "")
    monkeypatch.setattr(safety, "_BASELINES", {})     # else an earlier test's baseline is reused
    calls = []

    def fake_container(workdir, test_file, cfg):
        calls.append(test_file)
        return TestRun(ran=True, passed=True, isolated=True)

    monkeypatch.setattr(safety, "_run_in_container", fake_container)
    case = make_case(tmp_path, code=VULNERABLE_APP)
    result = verify(case, fix_for(case, FIXED_APP), CONFIG)
    assert calls == ["test_functional.py", "test_functional.py", "test_security.py"]
    assert result.functional_after.isolated is True


def test_a_container_timeout_kills_the_container(tmp_path, monkeypatch):
    from stages import safety
    names, killed = [], []

    def slow_docker(name, workdir, test_file, cfg):     # stands in for `docker run`
        names.append(name)
        return [sys.executable, "-c", "import time; time.sleep(30)"]

    def fake_run(cmd, **kwargs):                         # records `docker kill`
        killed.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(safety, "_docker_command", slow_docker)
    monkeypatch.setattr(safety.subprocess, "run", fake_run)
    cfg = dataclasses.replace(CONFIG, sandbox_timeout=1)
    result = safety._run_in_container(tmp_path, "test_functional.py", cfg)
    assert killed == [["docker", "kill", names[0]]]
    assert result.timed_out and result.isolated and not result.passed


# --- a fix may not forge its own verdict -------------------------------------

# BROKEN_APP is broken AND still vulnerable. This hook rewrites the junit report
# on exit so that every test "passed". Before the gate, verify() said ok=True.
FORGING_FIX = BROKEN_APP + '''
import atexit as _a, glob as _g, os as _o, re as _r, sys as _s
def _rewrite():
    path = next((x.split("=", 1)[1] for x in _s.argv if x.startswith("--junitxml=")), None)
    if path:
        names = [n for f in _g.glob("test_*.py")
                 for n in _r.findall(r"^def (test_\\w+)", open(f).read(), _r.M)]
        open(path, "w").write("<testsuites><testsuite>" + "".join(
            f'<testcase name="{n}"/>' for n in names) + "</testsuite></testsuites>")
    _o._exit(0)
_a.register(_rewrite)
'''


def test_a_fix_that_would_forge_its_report_is_never_run(tmp_path, functional_runs):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    result = verify(case, fix_for(case, FORGING_FIX), CONFIG)
    assert functional_runs == []                         # not even the baseline
    assert "import atexit" in result.disallowed and "_exit" in result.disallowed
    assert result.ok is False and result.applied is False
    assert "was NOT run" in result.feedback_for_repair


@pytest.mark.parametrize("added", [
    "pid = os.fork()",
    "os._exit(0)",
    "eval('1')",
    "m = __import__('atexit')",
    "g = find.__globals__",
    "from os import fork as f",
    "import ctypes",
])
def test_the_gate_flags_what_a_security_fix_never_adds(added):
    from stages.safety import _added_code_problems
    assert _added_code_problems("import os\n", f"import os\n{added}\n")


def test_the_gate_allows_what_security_fixes_add_and_what_the_original_had():
    from stages.safety import _added_code_problems
    original = "import os\nimport sys\nprint(sys.argv, eval('1'))\n"
    fixed = ("import hmac, secrets, shlex\nfrom pathlib import Path\nimport os\nimport sys\n"
             "print(sys.argv, eval('1'), Path(__file__).parent)\n")
    assert _added_code_problems(original, fixed) == []


DATASET = Path(__file__).resolve().parents[2] / "dataset"


@pytest.mark.skipif(not DATASET.is_dir(), reason="needs ../dataset")
def test_every_dataset_reference_fix_passes_the_gate():
    from stages.safety import _added_code_problems
    blocked = {}
    for case in sorted(DATASET.glob("case_*")):
        problems = _added_code_problems((case / "app.py").read_text(encoding="utf-8"),
                                        (case / "reference_fix.py").read_text(encoding="utf-8"))
        if problems:
            blocked[case.name] = problems
    assert blocked == {}


# --- fail closed --------------------------------------------------------------

def test_a_crashed_rescan_is_not_clear(tmp_path, monkeypatch):
    """Handing back the vulnerable file while bandit crashes must not pass."""
    from stages import safety

    def crash(*args, **kwargs):
        raise RuntimeError("bandit missing")

    monkeypatch.setattr(safety, "detect_code", crash)
    case = make_case(tmp_path, code=VULNERABLE_APP, with_security=False)
    result = verify(case, fix_for(case, VULNERABLE_APP), CONFIG)
    assert result.rescan_clear is False and result.vuln_gone is False
    assert result.ok is False
    assert "re-scan failed: RuntimeError: bandit missing" in result.feedback_for_repair


def test_security_tests_with_no_result_fail_closed(tmp_path, monkeypatch):
    from stages import safety
    real = safety._run_pytest

    def security_never_reports(workdir, test_file, cfg):
        if test_file == "test_security.py":
            return TestRun(ran=False, returncode=0, output="no test report (exit 0)")
        return real(workdir, test_file, cfg)

    monkeypatch.setattr(safety, "_run_pytest", security_never_reports)
    case = make_case(tmp_path, code=VULNERABLE_APP)
    result = verify(case, fix_for(case, FIXED_APP), CONFIG)
    assert result.security_verdict is False and result.vuln_gone is False
    assert "produced no result" in result.feedback_for_repair


def test_a_run_that_writes_no_report_did_not_run_and_is_not_cached(tmp_path, monkeypatch):
    from stages import safety
    monkeypatch.setattr(safety, "_BASELINES", {})
    case = make_case(tmp_path, code=VULNERABLE_APP)
    (case.path / "test_functional.py").write_text(
        "import os\n\n\ndef test_ends_the_process(mod):\n    os._exit(0)\n", encoding="utf-8")
    result = verify(case, fix_for(case, FIXED_APP), CONFIG)
    assert result.functional_baseline.ran is False
    assert result.functional_baseline.returncode == 0     # exit 0, and still not a pass
    assert result.functional_after.ran is False and result.ok is False
    assert safety._BASELINES == {}


# --- what comes back from a run is bounded and parsed defensively ------------

def test_output_is_capped_however_much_the_run_prints():
    from stages.safety import _run_capped
    returncode, output, timed_out = _run_capped(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 20_000_000 + 'END')"],
        timeout=60, limit=4000)
    assert returncode == 0 and not timed_out
    assert len(output) == 4000 and output.endswith("END")


def test_the_container_stream_splits_output_and_report():
    from stages.safety import REPORT_MARKER, _parse_report, _split_container_stream
    report = '<testsuites><testsuite><testcase name="test_a"/></testsuite></testsuites>'
    output, xml = _split_container_stream(f"1 passed\n{REPORT_MARKER} 0\n{report}")
    assert output == "1 passed" and _parse_report(xml) == {"test_a": True}
    # Docker failed before the shell ran: no marker, the error is the output
    output, xml = _split_container_stream("docker: Error response from daemon")
    assert xml is None and "Error response" in output


@pytest.mark.parametrize("xml", [
    None, "", "<testsuites><testsuite>",                          # missing, truncated
    '<!DOCTYPE x [<!ENTITY a "aaaa">]><testsuites/>',               # entity tricks
])
def test_an_unusable_report_is_no_report(xml):
    from stages.safety import _parse_report
    assert _parse_report(xml) is None


def _sandbox_ready() -> bool:
    from stages.safety import _docker_problem
    return _docker_problem(CONFIG) == ""


@pytest.mark.skipif(not _sandbox_ready(),
                    reason="needs Docker and `docker build -t aieval-sandbox sandbox`")
def test_inside_the_container_there_is_no_network_and_no_writable_case(tmp_path):
    case = make_case(tmp_path, code=VULNERABLE_APP)
    (case.path / "test_functional.py").write_text(
        "import socket\nfrom pathlib import Path\nimport pytest\n\n\n"
        "def test_no_network(mod):\n"
        "    with pytest.raises(OSError):\n"
        "        socket.create_connection(('1.1.1.1', 53), timeout=3)\n\n\n"
        "def test_case_folder_is_read_only(mod):\n"
        "    with pytest.raises(OSError):\n"
        "        Path('/case/pwned').write_text('x')\n\n\n"
        "def test_scratch_is_writable(mod, tmp_path):\n"
        "    (tmp_path / 'ok').write_text('x')\n",
        encoding="utf-8")
    result = verify(case, fix_for(case, FIXED_APP), CONFIG)
    assert result.functional_after.isolated is True
    assert result.functional_after.passed, result.functional_after.output
