"""Write CSV reports into an exports directory."""

import argparse
import csv
import os
from pathlib import Path

BASE_DIR = "exports"
SUFFIX = ".csv"
HEADER = ("name", "bytes")


def _inside_base(path, base):
    root = Path(base).resolve()
    return Path(path).resolve().is_relative_to(root)


def export_path(name, base=BASE_DIR):
    candidate = os.path.join(base, name)
    if not candidate.endswith(SUFFIX):
        candidate += SUFFIX
    if not _inside_base(candidate, base):
        raise ValueError(f"{name!r} is outside the export directory")
    return candidate


def folder_rows(folder):
    base = Path(folder)
    if not base.is_dir():
        return []
    return [(p.name, p.stat().st_size) for p in sorted(base.iterdir()) if p.is_file()]


def write_report(rows, name, base=BASE_DIR):
    path = export_path(name, base)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(HEADER)
        writer.writerows(rows)
    return path


def read_report(name, base=BASE_DIR):
    root = Path(base).resolve()
    path = (root / name).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"{name!r} is outside the export directory")
    with path.open(encoding="utf-8") as handle:
        return [tuple(row) for row in csv.reader(handle)]


def list_reports(base=BASE_DIR):
    root = Path(base)
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.suffix == SUFFIX)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export a folder listing as CSV")
    parser.add_argument("source")
    parser.add_argument("name")
    parser.add_argument("--base", default=BASE_DIR)
    args = parser.parse_args(argv)

    rows = folder_rows(args.source)
    path = write_report(rows, args.name, args.base)
    print(f"{path} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
