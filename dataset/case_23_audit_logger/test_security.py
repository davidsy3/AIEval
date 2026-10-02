import pytest


@pytest.fixture
def conn(mod):
    c = mod.open_log(":memory:")
    mod.record(c, "ada", "login", None, 1_700_000_000)
    mod.record(c, "bo", "export", "payroll", 1_700_000_060)
    return c


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_sqli_search_filters(mod, conn):
    assert not _run(mod.search, conn, {"actor": "nobody' OR '1'='1"})
    assert not _run(mod.search, conn, {"action": "nobody' OR actor = 'ada"})
    union = "nobody' UNION SELECT 1, name, sql, 'x', 0 FROM sqlite_master --"
    assert not _run(mod.search, conn, {"target": union})
    assert [e["actor"] for e in mod.search(conn, {"actor": "ada"})] == ["ada"]


def test_v2_command_execution_export_gzip(mod, conn, tmp_path):
    marker = tmp_path / "pwned"
    path = tmp_path / "audit.json"
    for dest in (
        f"{tmp_path}/out.gz; touch {marker}",
        f"{tmp_path}/out.gz $(touch {marker})",
        f"{tmp_path}/out.gz && touch {marker}",
    ):
        _run(mod.export_gzip, conn, str(path), dest)
    assert not marker.exists()
    assert mod.export_gzip(conn, str(path))["events"] == 2
