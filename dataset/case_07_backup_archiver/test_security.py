import os

import pytest


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("# demo\n")
    return root


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_command_execution_create_archive(mod, project, tmp_path):
    marker = tmp_path / "pwned"
    dest = str(tmp_path / "out")
    # Neither payload uses a forbidden token.
    _run(mod.create_archive, str(project), dest, f"nightly $(touch {marker})")
    _run(mod.create_archive, str(project), dest, f"nightly && touch {marker}")
    _run(mod.create_archive, str(project), dest, f"nightly\ntouch {marker}")
    assert not marker.exists()
    assert os.path.isfile(mod.create_archive(str(project), dest, "nightly"))
