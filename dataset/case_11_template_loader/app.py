"""Load and render plain-text email templates."""

import os
from string import Template

TEMPLATE_DIR = "templates"
SUFFIX = ".txt"


def _strip_parent_refs(name):
    """Drop parent-directory steps from a requested template name."""
    return name.replace("../", "")


def template_path(name, template_dir=TEMPLATE_DIR):
    return os.path.join(template_dir, _strip_parent_refs(name) + SUFFIX)


def available_templates(template_dir=TEMPLATE_DIR):
    if not os.path.isdir(template_dir):
        return []
    names = [n for n in os.listdir(template_dir) if n.endswith(SUFFIX)]
    return sorted(n[: -len(SUFFIX)] for n in names)


def load_template(name, template_dir=TEMPLATE_DIR):
    with open(template_path(name, template_dir), encoding="utf-8") as handle:
        return handle.read()


def placeholders(name, template_dir=TEMPLATE_DIR):
    text = load_template(name, template_dir)
    found = set()
    for match in Template.pattern.finditer(text):
        key = match.group("named") or match.group("braced")
        if key:
            found.add(key)
    return sorted(found)


def missing_keys(name, context, template_dir=TEMPLATE_DIR):
    return [key for key in placeholders(name, template_dir) if key not in context]


def render(name, context, template_dir=TEMPLATE_DIR):
    return Template(load_template(name, template_dir)).safe_substitute(context)


def subject_of(name, context=None, template_dir=TEMPLATE_DIR):
    text = render(name, context or {}, template_dir)
    first = text.splitlines()[0] if text else ""
    prefix = "Subject:"
    return first[len(prefix) :].strip() if first.startswith(prefix) else None


def body_of(name, context=None, template_dir=TEMPLATE_DIR):
    text = render(name, context or {}, template_dir)
    lines = text.splitlines()
    if lines and lines[0].startswith("Subject:"):
        lines = lines[1:]
    return "\n".join(lines).strip()
