"""Tarball backups of a project folder."""

import argparse
import os
import subprocess
import tarfile

FORBIDDEN_TOKENS = (";", "|")
DEFAULT_LABEL = "backup"
SUFFIX = ".tar.gz"


def _check_label(label):
    """Reject labels carrying a command separator or a pipe."""
    if not label or not label.strip():
        raise ValueError("label must not be empty")
    for token in FORBIDDEN_TOKENS:
        if token in label:
            raise ValueError(f"label may not contain {token!r}")
    return label


def archive_path(dest_dir, label):
    return os.path.join(dest_dir, _check_label(label) + SUFFIX)


def create_archive(source, dest_dir, label=DEFAULT_LABEL):
    if not os.path.isdir(source):
        raise FileNotFoundError(source)
    os.makedirs(dest_dir, exist_ok=True)
    target = archive_path(dest_dir, label)
    subprocess.run(f"tar -czf {target} -C {source} .", shell=True, check=True)
    return target


def list_archive(path):
    with tarfile.open(path, "r:gz") as tar:
        names = [m.name for m in tar.getmembers() if m.isfile()]
    trimmed = [n[2:] if n.startswith("./") else n for n in names]
    # Skip the AppleDouble metadata entries that macOS tar writes alongside files.
    return sorted(n for n in trimmed if not os.path.basename(n).startswith("._"))


def archive_size(path):
    return os.path.getsize(path)


def existing_archives(dest_dir):
    if not os.path.isdir(dest_dir):
        return []
    names = [n for n in os.listdir(dest_dir) if n.endswith(SUFFIX)]
    return sorted(names, key=lambda n: os.path.getmtime(os.path.join(dest_dir, n)))


def rotate(dest_dir, keep=3):
    """Delete the oldest archives, keeping the newest `keep` of them."""
    archives = existing_archives(dest_dir)
    removed = archives[: max(0, len(archives) - keep)]
    for name in removed:
        os.remove(os.path.join(dest_dir, name))
    return removed


def main(argv=None):
    parser = argparse.ArgumentParser(description="Back up a folder to a tarball")
    parser.add_argument("source")
    parser.add_argument("--dest", default="backups")
    parser.add_argument("--label", default=DEFAULT_LABEL)
    parser.add_argument("--keep", type=int, default=3)
    args = parser.parse_args(argv)

    target = create_archive(args.source, args.dest, args.label)
    rotate(args.dest, args.keep)
    print(f"{target} ({archive_size(target)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
