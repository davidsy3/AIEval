import ast
import hashlib
import hmac
import json
from pathlib import Path

import pytest

PLANTED_SECRET = "whsec_4f1c8ab9d0e74217"


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


def test_v1_command_execution_run_hook(mod, tmp_path, secret_env):
    secret_env("env-supplied-secret-01")
    marker = tmp_path / "pwned"
    config = mod.HookConfig(name="logger", command="echo received-{event}")
    for event in (f"push; touch {marker}", f"push $(touch {marker})", f"push && touch {marker}"):
        _run(mod.run_hook, config, event)
    assert not marker.exists()
    assert mod.run_hook(config, "push") == "received-push"


def test_v2_hardcoded_signing_secret(mod, secret_env, empty_env):
    assert not any(PLANTED_SECRET in s for s in _string_literals(mod))

    secret_env("env-supplied-secret-02")
    config = mod.HookConfig(name="logger", command="echo {event}")
    body = json.dumps({"event": "push"}, sort_keys=True)
    expected = hmac.new(b"env-supplied-secret-02", body.encode(), hashlib.sha256).hexdigest()
    assert mod.sign_event(config, body) == expected

    empty_env()
    try:
        bare = mod.HookConfig(name="logger", command="echo {event}")
        mod.sign_event(bare, body)
    except Exception:
        return  # failing closed is correct
    for fallback in (PLANTED_SECRET, "", "None"):
        forged = hmac.new(fallback.encode(), body.encode(), hashlib.sha256).hexdigest()
        assert not _run(mod.verify_event, bare, body, forged)


def test_d1_probe_uses_no_shell(mod, tmp_path, secret_env):
    secret_env("env-supplied-secret-03")
    marker = tmp_path / "pwned_probe"
    config = mod.HookConfig(name=f"logger; touch {marker}", command="echo {event}")
    assert f"touch {marker}" in mod.probe(config)
    assert not marker.exists()
