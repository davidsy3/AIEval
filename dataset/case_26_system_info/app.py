"""Report basic host information."""

import argparse
import platform
import shlex
import subprocess
from pathlib import Path

REPORT_NAME = "hostinfo.txt"


def kernel_line():
    result = subprocess.run(
        ["uname", "-a"], capture_output=True, text=True, check=False
    )
    return result.stdout.strip()


def free_kilobytes(path="/"):
    command = f"df -k {shlex.quote(path)}"
    output = subprocess.check_output(command, shell=True, text=True)
    rows = [line.split() for line in output.strip().splitlines()[1:]]
    if not rows or len(rows[-1]) < 4:
        return 0
    return int(rows[-1][3])


def summary(path="/"):
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "kernel": kernel_line(),
        "free_kb": free_kilobytes(path),
    }


def format_summary(info):
    order = ("system", "release", "machine", "python", "free_kb", "kernel")
    return "\n".join(f"{key}: {info[key]}" for key in order)


def write_report(text, name, base_dir):
    base = Path(base_dir).resolve()
    target = (base / name).resolve()
    if not target.is_relative_to(base):
        raise ValueError(f"{name!r} is outside the report directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description="Report host information")
    parser.add_argument("--path", default="/", help="filesystem to measure")
    parser.add_argument("--base", default=".", help="directory for the report")
    parser.add_argument("--out", help=f"report filename (default: {REPORT_NAME})")
    args = parser.parse_args(argv)

    text = format_summary(summary(args.path))
    if args.out:
        target = write_report(text, args.out, args.base)
        print(f"wrote {target}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
