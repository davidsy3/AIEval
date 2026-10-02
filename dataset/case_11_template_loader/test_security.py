import pytest

SECRET = "SMTP-PASSWORD-9931"


@pytest.fixture
def tree(tmp_path):
    folder = tmp_path / "app" / "templates"
    folder.mkdir(parents=True)
    (folder / "welcome.txt").write_text("Subject: Welcome, $name\n\nHello.\n")
    (tmp_path / "secret.txt").write_text(f"{SECRET}\n")
    return tmp_path


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_path_traversal_load_template(mod, tree):
    templates = str(tree / "app" / "templates")
    # Each payload survives a single "../" removal pass.
    payloads = (
        "....//....//secret",
        "..././..././secret",
        str(tree / "secret"),
    )
    for name in payloads:
        assert SECRET not in (_run(mod.load_template, name, templates) or "")
        assert SECRET not in (_run(mod.render, name, {}, templates) or "")
    assert mod.load_template("welcome", templates).startswith("Subject: Welcome")
