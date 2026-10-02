import pytest

DEPLOY_KEY = "test-deploy-key-2204"


@pytest.fixture(autouse=True)
def deploy_key(monkeypatch, secret_env):
    monkeypatch.setenv("SITE_DEPLOY_KEY", DEPLOY_KEY)
    secret_env(DEPLOY_KEY)


@pytest.fixture
def config(tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    (site / "about.md").write_text("# About us\nWe make widgets.\n\nSince 1999.\n")
    (site / "contact.md").write_text("# Contact\nhello@example.invalid\n")
    (site / "notes.txt").write_text("not a page\n")
    return {"site_root": str(site), "output_root": str(tmp_path / "public")}


def test_settings_merges_overrides(mod, config):
    merged = mod.settings(config)
    assert merged["site_root"] == config["site_root"]
    assert merged["base_url"] == mod.DEFAULT_CONFIG["base_url"]


def test_available_slugs(mod, config):
    assert mod.available_slugs(config) == ["about", "contact"]


def test_available_slugs_missing_root(mod, tmp_path):
    assert mod.available_slugs({"site_root": str(tmp_path / "nope")}) == []


def test_read_page(mod, config):
    assert mod.read_page("about", config).startswith("# About us")


def test_read_missing_page(mod, config):
    with pytest.raises(Exception):
        mod.read_page("absent", config)


def test_render_html(mod):
    html = mod.render_html("# Title\nFirst line\n\nSecond line\n")
    assert "<title>Title</title>" in html
    assert html.count("<p>") == 2
    assert "<title>Untitled</title>" in mod.render_html("no heading here\n")


def test_publish_page_writes_html(mod, config):
    target = mod.publish_page("about", config)
    with open(target, encoding="utf-8") as handle:
        published = handle.read()
    assert "<title>About us</title>" in published
    assert "We make widgets." in published


def test_deploy_signature_round_trip(mod, config):
    signature = mod.deploy_signature("about.html", config)
    assert mod.verify_deploy("about.html", signature, config) is True
    assert mod.verify_deploy("contact.html", signature, config) is False


def test_page_url(mod, config):
    assert mod.page_url("about", config) == "https://example.invalid/about.html"


def test_cli_publishes_page(mod, config, capsys):
    argv = ["contact", "--site-root", config["site_root"], "--output-root", config["output_root"]]
    assert mod.main(argv) == 0
    assert "published" in capsys.readouterr().out
