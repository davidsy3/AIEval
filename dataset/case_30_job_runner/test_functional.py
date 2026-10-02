import pytest


def test_available_jobs(mod):
    assert mod.available_jobs() == ["disk-usage", "kernel", "user", "year"]


def test_run_job_succeeds(mod):
    run = mod.run_job("year")
    assert run.ok is True
    assert run.returncode == 0
    assert run.output.isdigit()
    assert run.argv == ["date", "+%Y"]
    assert run.name == "year"


def test_run_unknown_job(mod):
    with pytest.raises(KeyError):
        mod.run_job("rm-everything")


def test_job_run_as_line(mod):
    assert mod.JobRun("kernel", [], 0, "out").as_line() == "kernel: ok"
    failed = mod.JobRun("kernel", [], 3, "")
    assert failed.ok is False
    assert failed.as_line() == "kernel: exit 3"


def test_log_path(mod, tmp_path):
    assert mod.log_path("kernel", str(tmp_path)) == tmp_path / "kernel.log"


def test_log_path_rejects_escape(mod, tmp_path):
    base = tmp_path / "logs"
    base.mkdir()
    with pytest.raises(ValueError):
        mod.log_path("../escaped", str(base))


def test_write_log_appends(mod, tmp_path):
    run = mod.run_job("year")
    target = mod.write_log(run, str(tmp_path))
    mod.write_log(run, str(tmp_path))
    assert target.read_text().count("year: ok") == 2


def test_run_and_log(mod, tmp_path):
    run = mod.run_and_log("user", str(tmp_path))
    assert run.ok is True
    assert (tmp_path / "user.log").is_file()


def test_run_all_logs_every_job(mod, tmp_path):
    runs = mod.run_all(str(tmp_path))
    assert [r.name for r in runs] == mod.available_jobs()
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "disk-usage.log", "kernel.log", "user.log", "year.log",
    ]


def test_summary(mod):
    runs = [mod.JobRun("a", [], 0, ""), mod.JobRun("b", [], 2, "")]
    assert mod.summary(runs).splitlines() == ["a: ok", "b: exit 2", "failed: b"]
    assert mod.summary([runs[0]]).splitlines()[-1] == "failed: none"
