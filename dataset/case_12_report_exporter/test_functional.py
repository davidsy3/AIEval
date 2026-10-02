import pytest


@pytest.fixture
def base(tmp_path):
    exports = tmp_path / "exports"
    exports.mkdir()
    return str(exports)


@pytest.fixture
def source(tmp_path):
    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "a.bin").write_bytes(b"0" * 10)
    (folder / "b.bin").write_bytes(b"0" * 20)
    (folder / "sub").mkdir()
    return str(folder)


def test_export_path_adds_suffix(mod, base):
    assert mod.export_path("q1", base).endswith("exports/q1.csv")
    assert mod.export_path("q1.csv", base).endswith("exports/q1.csv")


def test_folder_rows_files_only(mod, source):
    assert mod.folder_rows(source) == [("a.bin", 10), ("b.bin", 20)]


def test_folder_rows_missing_folder(mod, tmp_path):
    assert mod.folder_rows(str(tmp_path / "nope")) == []


def test_write_and_read_report(mod, base, source):
    path = mod.write_report(mod.folder_rows(source), "sizes", base)
    assert mod.read_report("sizes.csv", base) == [
        ("name", "bytes"),
        ("a.bin", "10"),
        ("b.bin", "20"),
    ]
    assert path.endswith("sizes.csv")


def test_write_report_into_subfolder(mod, base, source):
    mod.write_report(mod.folder_rows(source), "2024/q1", base)
    assert mod.read_report("2024/q1.csv", base)[0] == ("name", "bytes")


def test_list_reports(mod, base, source):
    mod.write_report([], "one", base)
    mod.write_report([], "two", base)
    assert mod.list_reports(base) == ["one.csv", "two.csv"]


def test_list_reports_missing_base(mod, tmp_path):
    assert mod.list_reports(str(tmp_path / "nope")) == []


def test_cli_writes_report(mod, base, source, capsys):
    assert mod.main([source, "cli", "--base", base]) == 0
    assert "2 rows" in capsys.readouterr().out
    assert mod.list_reports(base) == ["cli.csv"]
