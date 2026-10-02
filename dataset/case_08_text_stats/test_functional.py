import pytest


@pytest.fixture
def folder(tmp_path):
    (tmp_path / "alpha.txt").write_text("one two three\nfour five\n")
    (tmp_path / "beta.txt").write_text("single\n")
    (tmp_path / "notes.md").write_text("ignored by the suffix filter\n")
    return tmp_path


def test_stats_for_single_file(mod, folder):
    stats = mod.stats_for(str(folder / "alpha.txt"))
    assert (stats.name, stats.lines, stats.words, stats.characters) == ("alpha.txt", 2, 5, 24)


def test_stats_for_missing_file(mod, folder):
    with pytest.raises(Exception):
        mod.stats_for(str(folder / "gone.txt"))


def test_average_word_length(mod, folder):
    assert mod.stats_for(str(folder / "beta.txt")).average_word_length == 7.0
    assert mod.FileStats("empty.txt", 0, 0, 0).average_word_length == 0.0


def test_stats_for_folder_filters_by_suffix(mod, folder):
    names = [s.name for s in mod.stats_for_folder(str(folder))]
    assert names == ["alpha.txt", "beta.txt"]


def test_stats_for_folder_missing_dir(mod, tmp_path):
    assert mod.stats_for_folder(str(tmp_path / "nope")) == []


def test_totals(mod, folder):
    total = mod.totals(mod.stats_for_folder(str(folder)))
    assert (total.name, total.lines, total.words, total.characters) == ("TOTAL", 3, 6, 31)


def test_largest_ranked(mod, folder):
    ranked = mod.largest(mod.stats_for_folder(str(folder)), limit=1)
    assert [s.name for s in ranked] == ["alpha.txt"]


def test_format_table(mod, folder):
    lines = mod.format_table(mod.stats_for_folder(str(folder))).splitlines()
    assert lines[0].startswith("file")
    assert lines[1].startswith("alpha.txt")
    assert lines[-1].startswith("TOTAL")
