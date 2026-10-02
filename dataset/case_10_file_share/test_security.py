import pytest

SECRET = "PRIVATE-KEY-MATERIAL-4417"


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "share"
    root.mkdir()
    (root / "report.txt").write_text("quarterly numbers\n")
    (tmp_path / "secret.txt").write_text(f"{SECRET}\n")
    return tmp_path


@pytest.fixture
def share(mod, tree):
    return mod.FileShare(str(tree / "share"))


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_path_traversal_download(share, tree):
    outside = str(tree / "secret.txt")
    for name in ("../secret.txt", "./../secret.txt", outside):
        payload = _run(share.download, name)
        assert SECRET.encode() not in (payload or b"")
        assert SECRET not in (_run(share.preview, name) or "")
        assert _run(share.info, name) is None
        assert _run(share.exists, name) in (None, False)
    assert share.download("report.txt") == b"quarterly numbers\n"
