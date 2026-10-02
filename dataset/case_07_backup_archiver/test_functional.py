import os

import pytest


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.py").write_text("print('hi')\n")
    (root / "README.md").write_text("# demo\n")
    return root


def test_archive_path_uses_label(mod, tmp_path):
    assert mod.archive_path(str(tmp_path), "nightly") == str(tmp_path / "nightly.tar.gz")


def test_archive_path_rejects_forbidden_label(mod, tmp_path):
    with pytest.raises(ValueError):
        mod.archive_path(str(tmp_path), "night;ly")
    with pytest.raises(ValueError):
        mod.archive_path(str(tmp_path), "  ")


def test_create_archive_contents(mod, project, tmp_path):
    target = mod.create_archive(str(project), str(tmp_path / "out"), "nightly")
    assert os.path.isfile(target)
    assert mod.list_archive(target) == ["README.md", "src/main.py"]
    assert mod.archive_size(target) > 0


def test_create_archive_missing_source(mod, tmp_path):
    with pytest.raises(FileNotFoundError):
        mod.create_archive(str(tmp_path / "gone"), str(tmp_path / "out"), "nightly")


def test_existing_archives_oldest_first(mod, project, tmp_path):
    dest = str(tmp_path / "out")
    for index, label in enumerate(["one", "two", "three"]):
        target = mod.create_archive(str(project), dest, label)
        os.utime(target, (1_700_000_000 + index, 1_700_000_000 + index))
    assert mod.existing_archives(dest) == ["one.tar.gz", "two.tar.gz", "three.tar.gz"]


def test_rotate_keeps_newest(mod, project, tmp_path):
    dest = str(tmp_path / "out")
    for index, label in enumerate(["one", "two", "three"]):
        target = mod.create_archive(str(project), dest, label)
        os.utime(target, (1_700_000_000 + index, 1_700_000_000 + index))
    assert mod.rotate(dest, keep=2) == ["one.tar.gz"]
    assert mod.existing_archives(dest) == ["two.tar.gz", "three.tar.gz"]


def test_cli_creates_archive(mod, project, tmp_path, capsys):
    dest = tmp_path / "out"
    assert mod.main([str(project), "--dest", str(dest), "--label", "cli"]) == 0
    assert "cli.tar.gz" in capsys.readouterr().out
    assert (dest / "cli.tar.gz").is_file()
