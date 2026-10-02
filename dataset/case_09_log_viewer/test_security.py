import hashlib

import pytest

SECRET = "ROOT-CREDENTIAL-8812"


@pytest.fixture
def tree(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "web.log").write_text("INFO boot\nERROR upstream timeout\n")
    (tmp_path / "secret.txt").write_text(f"{SECRET}\n")
    return tmp_path


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_path_traversal_read_log(mod, tree):
    log_dir = str(tree / "logs")
    outside = str(tree / "secret.txt")
    for name in ("../secret.txt", "..//secret.txt", "logs/../../secret.txt", outside):
        assert SECRET not in (_run(mod.read_log, name, log_dir) or "")
        assert SECRET not in (_run(mod.tail, name, 5, log_dir) or "")
        served = _run(mod.serve, name, 5, log_dir)
        assert SECRET not in (served or {}).get("body", "")
    assert mod.read_log("web.log", log_dir).startswith("INFO boot")


def test_d1_etag_md5_is_non_security_use(mod, tree, monkeypatch):
    log_dir = str(tree / "logs")
    real_md5 = hashlib.md5
    calls = []

    def strict_md5(*args, **kwargs):
        calls.append(kwargs)
        if kwargs.get("usedforsecurity", True):
            raise ValueError("md5 used in a security context")
        return real_md5(*args, **kwargs)

    monkeypatch.setattr(hashlib, "md5", strict_md5)
    assert len(mod.etag("web.log", log_dir)) == 32
    assert calls and all(c.get("usedforsecurity") is False for c in calls)
