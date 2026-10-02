"""Run named maintenance jobs from a fixed registry."""

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

JOBS = {
    "disk-usage": ["df", "-k", "/"],
    "kernel": ["uname", "-a"],
    "user": ["id", "-un"],
    "year": ["date", "+%Y"],
}
DEFAULT_TIMEOUT = 10
LOG_SUFFIX = ".log"


@dataclass
class JobRun:
    name: str
    argv: list = field(default_factory=list)
    returncode: int = 0
    output: str = ""
    at: float = field(default_factory=time.time)

    @property
    def ok(self):
        return self.returncode == 0

    def as_line(self):
        state = "ok" if self.ok else f"exit {self.returncode}"
        return f"{self.name}: {state}"


def available_jobs():
    return sorted(JOBS)


def run_job(name, timeout=DEFAULT_TIMEOUT):
    argv = JOBS[name]
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )
    return JobRun(name, list(argv), result.returncode, result.stdout.strip())


def log_path(name, log_dir):
    base = Path(log_dir).resolve()
    target = (base / (name + LOG_SUFFIX)).resolve()
    if not target.is_relative_to(base):
        raise ValueError(f"{name!r} is outside the log directory")
    return target


def write_log(run, log_dir):
    target = log_path(run.name, log_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(f"{int(run.at)} {run.as_line()}\n{run.output}\n")
    return target


def run_and_log(name, log_dir, timeout=DEFAULT_TIMEOUT):
    run = run_job(name, timeout)
    write_log(run, log_dir)
    return run


def run_all(log_dir=None, timeout=DEFAULT_TIMEOUT):
    runs = []
    for name in available_jobs():
        run = run_job(name, timeout)
        if log_dir is not None:
            write_log(run, log_dir)
        runs.append(run)
    return runs


def summary(runs):
    lines = [run.as_line() for run in runs]
    failed = [run.name for run in runs if not run.ok]
    lines.append(f"failed: {', '.join(failed) if failed else 'none'}")
    return "\n".join(lines)
