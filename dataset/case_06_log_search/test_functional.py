import pytest


@pytest.fixture
def logs(tmp_path):
    (tmp_path / "web.log").write_text(
        "INFO started\nERROR upstream timeout\nINFO ok\nERROR upstream reset\n"
    )
    (tmp_path / "db.log").write_text("INFO connected\nERROR deadlock\n")
    (tmp_path / "notes.txt").write_text("ERROR not a log file\n")
    return tmp_path


@pytest.fixture
def searcher(mod, logs):
    return mod.LogSearcher(str(logs))


def test_files_lists_logs_only(searcher):
    assert searcher.files() == ["db.log", "web.log"]


def test_files_missing_dir(mod, tmp_path):
    assert mod.LogSearcher(str(tmp_path / "nope")).files() == []


def test_count_matches(searcher):
    assert searcher.count_matches("ERROR", "web.log") == 2
    assert searcher.count_matches("WARN", "web.log") == 0


def test_count_matches_unknown_file(searcher):
    with pytest.raises(FileNotFoundError):
        searcher.count_matches("ERROR", "missing.log")


def test_count_all_and_busiest(searcher):
    assert searcher.count_all("ERROR") == {"db.log": 1, "web.log": 2}
    assert searcher.busiest_file("ERROR") == "web.log"


def test_busiest_file_empty_dir(mod, tmp_path):
    assert mod.LogSearcher(str(tmp_path)).busiest_file("ERROR") is None


def test_sample_lines_respects_limit(searcher):
    assert searcher.sample_lines("ERROR", "web.log") == [
        "ERROR upstream timeout",
        "ERROR upstream reset",
    ]
    assert searcher.sample_lines("ERROR", "web.log", limit=1) == ["ERROR upstream timeout"]


def test_summary(searcher):
    assert searcher.summary("ERROR").splitlines() == ["db.log: 1", "web.log: 2", "total: 3"]
