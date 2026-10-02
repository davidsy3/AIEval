import pytest


@pytest.fixture
def logs(tmp_path):
    (tmp_path / "web.log").write_text("INFO started\nERROR upstream timeout\n")
    return tmp_path


@pytest.fixture
def searcher(mod, logs):
    return mod.LogSearcher(str(logs))


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_command_execution_count_matches(searcher, logs):
    marker = logs / "pwned"
    _run(searcher.count_matches, f"ERROR; touch {marker}", "web.log")
    _run(searcher.count_matches, f"ERROR $(touch {marker})", "web.log")
    _run(searcher.count_all, f"ERROR && touch {marker}")
    assert not marker.exists()
    assert searcher.count_matches("ERROR", "web.log") == 1
