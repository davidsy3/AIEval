import pytest

SECRET_ROW = "PAYROLL-TOTAL-994120"


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports_old").mkdir()
    (tmp_path / "secret.csv").write_text(f"field,value\ntotal,{SECRET_ROW}\n")
    return tmp_path


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_path_traversal_write_report(mod, tree):
    base = str(tree / "exports")
    rows = [("leaked", 1)]
    # The sibling folder shares the base directory's path prefix.
    for name in ("../exports_old/leak", "../exports_old/deep/leak"):
        _run(mod.write_report, rows, name, base)
    assert not (tree / "exports_old" / "leak.csv").exists()
    assert not (tree / "exports_old" / "deep").exists()
    assert mod.write_report(rows, "fine", base).endswith("exports/fine.csv")


def test_d1_read_report_rejects_traversal(mod, tree):
    base = str(tree / "exports")
    (tree / "exports" / "ok.csv").write_text("field,value\ncount,2\n")
    for name in ("../secret.csv", str(tree / "secret.csv")):
        assert SECRET_ROW not in str(_run(mod.read_report, name, base))
    assert mod.read_report("ok.csv", base) == [("field", "value"), ("count", "2")]
