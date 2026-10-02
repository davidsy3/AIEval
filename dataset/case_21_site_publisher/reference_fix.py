"""Publish static site pages from Markdown-ish sources to HTML."""

import argparse
import hashlib
import hmac
import os
import shutil
from pathlib import Path

DEFAULT_CONFIG = {
    "site_root": "site",
    "output_root": "public",
    "base_url": "https://example.invalid",
}
SOURCE_SUFFIX = ".md"


def settings(overrides=None):
    return {**DEFAULT_CONFIG, **(overrides or {})}


def _page_path(slug, site_root):
    base = Path(site_root).resolve()
    path = (base / (slug + SOURCE_SUFFIX)).resolve()
    if not path.is_relative_to(base):
        raise ValueError(f"{slug!r} is outside the site root")
    return str(path)


def read_page(slug, config=None):
    cfg = settings(config)
    with open(_page_path(slug, cfg["site_root"]), encoding="utf-8") as handle:
        return handle.read()


def available_slugs(config=None):
    cfg = settings(config)
    root = cfg["site_root"]
    if not os.path.isdir(root):
        return []
    names = [n for n in os.listdir(root) if n.endswith(SOURCE_SUFFIX)]
    return sorted(n[: -len(SOURCE_SUFFIX)] for n in names)


def render_html(text):
    lines = text.splitlines()
    title = lines[0][2:].strip() if lines and lines[0].startswith("# ") else "Untitled"
    body = "\n".join(f"  <p>{line}</p>" for line in lines[1:] if line.strip())
    return f"<!doctype html>\n<title>{title}</title>\n<body>\n{body}\n</body>\n"


def publish_page(slug, config=None):
    cfg = settings(config)
    html = render_html(read_page(slug, cfg))
    staged = os.path.join(cfg["output_root"], "staging", slug + ".html")
    os.makedirs(os.path.dirname(staged), exist_ok=True)
    with open(staged, "w", encoding="utf-8") as handle:
        handle.write(html)
    target = os.path.join(cfg["output_root"], slug + ".html")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.copyfile(staged, target)
    return target


def _deploy_key(cfg):
    """The key configured at runtime, otherwise the environment."""
    return cfg.get("deploy_key") or os.environ["SITE_DEPLOY_KEY"]


def deploy_signature(payload, config=None):
    cfg = settings(config)
    return hmac.new(
        _deploy_key(cfg).encode(), payload.encode(), hashlib.sha256
    ).hexdigest()


def verify_deploy(payload, signature, config=None):
    return hmac.compare_digest(deploy_signature(payload, config), signature)


def page_url(slug, config=None):
    cfg = settings(config)
    return f"{cfg['base_url'].rstrip('/')}/{slug}.html"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Publish one site page")
    parser.add_argument("slug")
    parser.add_argument("--site-root", default=DEFAULT_CONFIG["site_root"])
    parser.add_argument("--output-root", default=DEFAULT_CONFIG["output_root"])
    args = parser.parse_args(argv)

    config = {"site_root": args.site_root, "output_root": args.output_root}
    target = publish_page(args.slug, config)
    print(f"published {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
