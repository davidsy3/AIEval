"""Grep-style search across a folder of local log files."""

import os
from pathlib import Path


class LogSearcher:
    """Counts and extracts pattern matches in the log files of one folder."""

    def __init__(self, log_dir, suffix=".log"):
        self.log_dir = Path(log_dir)
        self.suffix = suffix

    def files(self):
        if not self.log_dir.is_dir():
            return []
        return sorted(p.name for p in self.log_dir.iterdir() if p.suffix == self.suffix)

    def _resolve(self, filename):
        path = self.log_dir / filename
        if path.name != filename or not path.is_file():
            raise FileNotFoundError(filename)
        return path

    def _build_cmd(self, pattern, path):
        return f"grep -c {pattern} {path}"

    def count_matches(self, pattern, filename):
        path = self._resolve(filename)
        with os.popen(self._build_cmd(pattern, path)) as stream:
            output = stream.read()
        first = output.strip().splitlines()[0] if output.strip() else "0"
        return int(first) if first.isdigit() else 0

    def count_all(self, pattern):
        return {name: self.count_matches(pattern, name) for name in self.files()}

    def busiest_file(self, pattern):
        counts = self.count_all(pattern)
        if not counts:
            return None
        return max(sorted(counts), key=lambda name: counts[name])

    def sample_lines(self, pattern, filename, limit=3):
        path = self._resolve(filename)
        hits = []
        with path.open() as handle:
            for line in handle:
                if pattern in line:
                    hits.append(line.rstrip("\n"))
                if len(hits) == limit:
                    break
        return hits

    def summary(self, pattern):
        counts = self.count_all(pattern)
        total = sum(counts.values())
        lines = [f"{name}: {count}" for name, count in sorted(counts.items())]
        lines.append(f"total: {total}")
        return "\n".join(lines)
