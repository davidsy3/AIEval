import pytest


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "notes.txt").write_bytes(b"x" * 40_000)
    (tmp_path / "media").mkdir()
    (tmp_path / "media" / "clip.bin").write_bytes(b"y" * 200_000)
    (tmp_path / "empty").mkdir()
    (tmp_path / "loose.txt").write_text("not a folder")
    return tmp_path


def test_folder_size_kb(mod, tree):
    assert mod.folder_size_kb(str(tree / "media")) >= 195
    assert mod.folder_size_kb(str(tree / "docs")) >= 39


def test_list_folders(mod, tree):
    assert mod.list_folders(str(tree)) == ["docs", "empty", "loose.txt", "media"]


def test_list_folders_missing_base(mod, tmp_path):
    assert mod.list_folders(str(tmp_path / "nope")) == []


def test_usage_report_covers_directories_only(mod, tree):
    report = mod.usage_report(str(tree))
    assert set(report) == {"docs", "empty", "media"}
    assert report["media"] > report["docs"]


def test_human_size(mod):
    assert mod.human_size(0) == "0.0 KB"
    assert mod.human_size(512) == "512.0 KB"
    assert mod.human_size(2048) == "2.0 MB"


def test_largest_folders_ranked(mod, tree):
    assert [name for name, _ in mod.largest_folders(str(tree))] == ["media", "docs", "empty"]
    assert len(mod.largest_folders(str(tree), limit=1)) == 1


def test_format_report(mod, tree):
    text = mod.format_report(str(tree))
    assert text.splitlines()[0].startswith("Disk usage under ")
    assert "media" in text
    assert text.strip().splitlines()[-1].lstrip().startswith("TOTAL")
