import pytest


@pytest.fixture
def templates(tmp_path):
    folder = tmp_path / "templates"
    folder.mkdir()
    (folder / "welcome.txt").write_text(
        "Subject: Welcome, $name\n\nYour account at $site is ready.\n"
    )
    (folder / "receipt.txt").write_text("Subject: Receipt ${order}\n\nTotal: $amount\n")
    (folder / "notes.md").write_text("ignored\n")
    return str(folder)


def test_available_templates(mod, templates):
    assert mod.available_templates(templates) == ["receipt", "welcome"]


def test_available_templates_missing_dir(mod, tmp_path):
    assert mod.available_templates(str(tmp_path / "nope")) == []


def test_load_template(mod, templates):
    assert mod.load_template("welcome", templates).startswith("Subject: Welcome, $name")


def test_load_missing_template(mod, templates):
    with pytest.raises(Exception):
        mod.load_template("nothing", templates)


def test_placeholders(mod, templates):
    assert mod.placeholders("welcome", templates) == ["name", "site"]
    assert mod.placeholders("receipt", templates) == ["amount", "order"]


def test_missing_keys(mod, templates):
    assert mod.missing_keys("welcome", {"name": "Ada"}, templates) == ["site"]
    assert mod.missing_keys("welcome", {"name": "Ada", "site": "x"}, templates) == []


def test_render_substitutes_and_keeps_unknown(mod, templates):
    out = mod.render("welcome", {"name": "Ada"}, templates)
    assert "Welcome, Ada" in out
    assert "$site" in out


def test_subject_and_body(mod, templates):
    context = {"name": "Ada", "site": "Example"}
    assert mod.subject_of("welcome", context, templates) == "Welcome, Ada"
    assert mod.body_of("welcome", context, templates) == "Your account at Example is ready."


def test_subject_none_without_header(mod, templates, tmp_path):
    (tmp_path / "templates" / "plain.txt").write_text("no header here\n")
    assert mod.subject_of("plain", {}, templates) is None
