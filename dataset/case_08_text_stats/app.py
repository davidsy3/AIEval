"""Line, word and character counts for text files, via the system wc tool."""

import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SUFFIX = ".txt"


@dataclass(frozen=True)
class FileStats:
    name: str
    lines: int
    words: int
    characters: int

    @property
    def average_word_length(self):
        if not self.words:
            return 0.0
        return round(self.characters / self.words, 2)

    def as_row(self):
        return f"{self.name:<24}{self.lines:>8}{self.words:>8}{self.characters:>10}"


def _wc_command(path):
    return f'wc -lwc "{shlex.quote(path)}"'


def stats_for(path):
    output = subprocess.check_output(_wc_command(path), shell=True, text=True)
    lines, words, characters = (int(value) for value in output.split()[:3])
    return FileStats(os.path.basename(path), lines, words, characters)


def stats_for_folder(folder, suffix=DEFAULT_SUFFIX):
    base = Path(folder)
    if not base.is_dir():
        return []
    return [stats_for(str(p)) for p in sorted(base.iterdir()) if p.suffix == suffix]


def totals(stats):
    return FileStats(
        "TOTAL",
        sum(s.lines for s in stats),
        sum(s.words for s in stats),
        sum(s.characters for s in stats),
    )


def largest(stats, limit=3):
    return sorted(stats, key=lambda s: (-s.characters, s.name))[:limit]


def format_table(stats):
    header = f"{'file':<24}{'lines':>8}{'words':>8}{'chars':>10}"
    rows = [s.as_row() for s in stats]
    rows.append(totals(stats).as_row())
    return "\n".join([header] + rows)
