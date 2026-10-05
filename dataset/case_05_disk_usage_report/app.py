"""Per-folder disk usage summary built on the system du/ls tools."""

import os
import subprocess

UNITS = (("GB", 1024 * 1024), ("MB", 1024), ("KB", 1))


def folder_size_kb(folder):
    """Return the size of one folder in kilobytes, as reported by du."""
    output = subprocess.check_output(f"du -sk {folder}", shell=True, text=True)
    return int(output.split()[0])


def list_folders(base):
    """Return the immediate entry names under base, sorted."""
    result = subprocess.run(
        ["ls", "-1", base], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return []
    names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return sorted(names)


def usage_report(base):
    """Map each subfolder of base to its size in kilobytes."""
    report = {}
    for name in list_folders(base):
        path = os.path.join(base, name)
        if os.path.isdir(path):
            report[name] = folder_size_kb(path)
    return report


def human_size(kilobytes):
    for suffix, factor in UNITS:
        if kilobytes >= factor:
            return f"{kilobytes / factor:.1f} {suffix}"
    return "0.0 KB"


def largest_folders(base, limit=3):
    report = usage_report(base)
    ranked = sorted(report.items(), key=lambda item: (-item[1], item[0]))
    return ranked[:limit]


def format_report(base, limit=3):
    lines = [f"Disk usage under {base}"]
    for name, kilobytes in largest_folders(base, limit):
        lines.append(f"  {name:<24} {human_size(kilobytes):>10}")
    total = folder_size_kb(base)
    lines.append(f"  {'TOTAL':<24} {human_size(total):>10}")
    return "\n".join(lines)
