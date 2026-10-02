import pytest


@pytest.fixture
def folder(tmp_path):
    (tmp_path / "alpha.txt").write_text("one two three\nfour five\n")
    return tmp_path


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_command_execution_stats_for(mod, folder):
    marker = folder / "pwned"
    target = folder / "alpha.txt"
    # shlex.quote single-quotes these, but the quotes are literal inside "..."
    _run(mod.stats_for, f"{target} $(touch {marker})")
    _run(mod.stats_for, f"$(touch {marker})")
    _run(mod.stats_for, f"{target}`touch {marker}`")
    assert not marker.exists()
    assert mod.stats_for(str(target)).words == 5
