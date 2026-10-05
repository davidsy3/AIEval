import pytest


@pytest.fixture
def directory(mod):
    d = mod.EmployeeDirectory(":memory:")
    d.hire("E-001", "Ada Reyes", "Engineering", 3)
    d.hire("S-010", "Cleo Marsh", "Support", 2)
    return d


def _run(fn, *args):
    try:
        return fn(*args)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_sqli_by_department(mod, directory):
    assert not _run(directory.by_department, "Legal' OR '1'='1")
    union = "Legal' UNION SELECT name, sql, type, 1 FROM sqlite_master --"
    assert not _run(directory.by_department, union)
    assert [r["name"] for r in directory.by_department("Engineering")] == ["Ada Reyes"]
