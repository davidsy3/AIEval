import pytest


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_d1_kernel_line_uses_no_shell(mod, tmp_path, monkeypatch):
    marker = tmp_path / "pwned_uname"
    monkeypatch.chdir(tmp_path)
    assert mod.kernel_line()
    assert not marker.exists()
    assert not list(tmp_path.glob("pwned*"))


def test_d2_free_kilobytes_quotes_its_argument(mod, tmp_path):
    marker = tmp_path / "pwned_df"
    for path in (
        f"{tmp_path}; touch {marker}",
        f"{tmp_path} $(touch {marker})",
        f"{tmp_path} && touch {marker}",
        f"{tmp_path}`touch {marker}`",
    ):
        _run(mod.free_kilobytes, path)
    assert not marker.exists()
    assert mod.free_kilobytes(str(tmp_path)) > 0


def test_d3_write_report_stays_under_base(mod, tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "escaped.txt"
    for name in ("../escaped.txt", "./../escaped.txt", str(outside)):
        assert _run(mod.write_report, "leaked", name, str(base)) is None
    assert not outside.exists()
    assert mod.write_report("fine", "report.txt", str(base)).is_file()
