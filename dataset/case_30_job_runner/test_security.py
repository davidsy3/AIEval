import pytest


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_d1_job_argv_comes_from_the_registry(mod, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    marker = tmp_path / "pwned"
    for name in (
        f"year; touch {marker}",
        "year && touch pwned",
        f"year $(touch {marker})",
        "kernel | touch pwned",
    ):
        assert _run(mod.run_job, name) is None
        assert _run(mod.run_and_log, name, str(tmp_path)) is None
    assert not marker.exists()
    assert not list(tmp_path.glob("pwned*"))
    assert all(isinstance(argv, list) for argv in mod.JOBS.values())
    assert mod.run_job("year").ok is True


def test_d2_log_path_stays_under_log_dir(mod, tmp_path):
    base = tmp_path / "logs"
    base.mkdir()
    outside = tmp_path / "escaped.log"
    for name in ("../escaped", "./../escaped", str(tmp_path / "escaped")):
        assert _run(mod.log_path, name, str(base)) is None
        assert _run(mod.write_log, mod.JobRun(name, [], 0, "leaked"), str(base)) is None
    assert not outside.exists()
    assert mod.log_path("kernel", str(base)) == base / "kernel.log"
