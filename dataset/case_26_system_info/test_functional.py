import pytest


def test_kernel_line(mod):
    line = mod.kernel_line()
    assert line
    assert len(line.split()) >= 3


def test_free_kilobytes(mod, tmp_path):
    assert mod.free_kilobytes("/") > 0
    assert mod.free_kilobytes(str(tmp_path)) > 0


def test_free_kilobytes_missing_path(mod, tmp_path):
    with pytest.raises(Exception):
        mod.free_kilobytes(str(tmp_path / "nope"))


def test_summary_keys(mod):
    info = mod.summary()
    assert set(info) == {"system", "release", "machine", "python", "kernel", "free_kb"}
    assert info["system"]
    assert isinstance(info["free_kb"], int)


def test_format_summary_order(mod):
    info = {
        "system": "Linux", "release": "6.1", "machine": "x86_64",
        "python": "3.12.0", "kernel": "Linux demo 6.1", "free_kb": 1024,
    }
    lines = mod.format_summary(info).splitlines()
    assert [line.split(":")[0] for line in lines] == [
        "system", "release", "machine", "python", "free_kb", "kernel",
    ]


def test_write_report(mod, tmp_path):
    target = mod.write_report("hello", "hostinfo.txt", str(tmp_path))
    assert target.read_text() == "hello"
    nested = mod.write_report("hello", "reports/host.txt", str(tmp_path))
    assert nested.is_file()


def test_write_report_rejects_escape(mod, tmp_path):
    with pytest.raises(ValueError):
        mod.write_report("hello", "../escaped.txt", str(tmp_path / "base"))


def test_cli_prints_summary(mod, capsys):
    assert mod.main([]) == 0
    assert "system:" in capsys.readouterr().out


def test_cli_writes_report(mod, tmp_path, capsys):
    assert mod.main(["--base", str(tmp_path), "--out", "info.txt"]) == 0
    assert "wrote" in capsys.readouterr().out
    assert (tmp_path / "info.txt").is_file()
