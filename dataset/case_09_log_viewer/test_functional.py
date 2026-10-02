import pytest


@pytest.fixture
def log_dir(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "web.log").write_text(
        "INFO boot\nERROR upstream timeout\nINFO ready\nERROR upstream reset\n"
    )
    (logs / "db.log").write_text("INFO connected\n")
    (logs / "README").write_text("not a log\n")
    return str(logs)


def test_available_logs(mod, log_dir):
    assert mod.available_logs(log_dir) == ["db.log", "web.log"]


def test_available_logs_missing_dir(mod, tmp_path):
    assert mod.available_logs(str(tmp_path / "nope")) == []


def test_read_log(mod, log_dir):
    assert mod.read_log("db.log", log_dir) == "INFO connected\n"


def test_read_missing_log(mod, log_dir):
    with pytest.raises(Exception):
        mod.read_log("gone.log", log_dir)


def test_tail_limits_lines(mod, log_dir):
    assert mod.tail("web.log", 2, log_dir).splitlines() == [
        "INFO ready",
        "ERROR upstream reset",
    ]
    assert len(mod.tail("web.log", log_dir=log_dir).splitlines()) == 4


def test_etag_is_stable_and_content_bound(mod, log_dir, tmp_path):
    first = mod.etag("web.log", log_dir)
    assert first == mod.etag("web.log", log_dir)
    (tmp_path / "logs" / "web.log").write_text("INFO boot\n")
    assert mod.etag("web.log", log_dir) != first


def test_level_counts(mod, log_dir):
    assert mod.level_counts("web.log", log_dir) == {"INFO": 2, "ERROR": 2}


def test_serve_payload(mod, log_dir):
    payload = mod.serve("web.log", 2, log_dir)
    assert payload["name"] == "web.log"
    assert payload["lines"] == 2
    assert len(payload["etag"]) == 32
    assert payload["body"].endswith("ERROR upstream reset")


def test_index_reports_sizes(mod, log_dir):
    rows = mod.index(log_dir)
    assert [r["name"] for r in rows] == ["db.log", "web.log"]
    assert rows[0]["bytes"] == len("INFO connected\n")
