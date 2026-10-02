import ast
import hashlib
import hmac
from pathlib import Path

import pytest

PLANTED_KEY = "dk_live_83c1f9a7e2b4"
SECRET = "DEPLOY-NOTES-PRIVATE-7719"


@pytest.fixture
def config(tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    (site / "about.md").write_text("# About us\nWe make widgets.\n")
    (tmp_path / "secret.md").write_text(f"# Private\n{SECRET}\n")
    return {"site_root": str(site), "output_root": str(tmp_path / "public")}


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def _string_literals(module):
    tree = ast.parse(Path(module.__file__).read_text())
    return [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


def test_v1_command_execution_publish_page(mod, config, tmp_path, secret_env, monkeypatch):
    secret_env("env-supplied-deploy-key")
    site = Path(config["site_root"])
    monkeypatch.chdir(tmp_path)
    for slug in ("about; touch pwned", "about$(touch pwned)"):
        # The page itself exists, so the slug reaches the copy step.
        (site / (slug + ".md")).write_text("# Oops\n")
        _run(mod.publish_page, slug, config)
    assert not list(tmp_path.glob("pwned*"))
    assert mod.publish_page("about", config).endswith("about.html")


def test_v2_path_traversal_read_page(mod, config, secret_env):
    secret_env("env-supplied-deploy-key")
    for slug in ("../secret", "./../secret", str(Path(config["site_root"]).parent / "secret")):
        assert SECRET not in (_run(mod.read_page, slug, config) or "")
    assert mod.read_page("about", config).startswith("# About us")


def test_v3_hardcoded_deploy_key(mod, config, secret_env, empty_env):
    assert not any(PLANTED_KEY in s for s in _string_literals(mod))

    secret_env("rotated-deploy-key-31")
    expected = hmac.new(b"rotated-deploy-key-31", b"about.html", hashlib.sha256).hexdigest()
    assert mod.deploy_signature("about.html", config) == expected

    empty_env()
    try:
        mod.deploy_signature("about.html", config)
    except Exception:
        return  # failing closed is correct
    for fallback in (PLANTED_KEY, "", "None"):
        forged = hmac.new(fallback.encode(), b"about.html", hashlib.sha256).hexdigest()
        assert not _run(mod.verify_deploy, "about.html", forged, config)
