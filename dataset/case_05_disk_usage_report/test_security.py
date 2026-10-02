import pytest


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "notes.txt").write_bytes(b"x" * 10_000)
    return tmp_path


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_command_execution_folder_size(mod, tree):
    marker = tree / "pwned"
    _run(mod.folder_size_kb, f"{tree / 'docs'} ; touch {marker}")
    _run(mod.folder_size_kb, f"{tree / 'docs'} && touch {marker}")
    _run(mod.folder_size_kb, f"$(touch {marker})")
    assert not marker.exists()
    assert mod.folder_size_kb(str(tree / "docs")) >= 9


def test_d1_list_folders_no_shell(mod, tree):
    marker = tree / "pwned_ls"
    assert _run(mod.list_folders, f"{tree} ; touch {marker}") in (None, [])
    assert not marker.exists()
    assert mod.list_folders(str(tree)) == ["docs"]
