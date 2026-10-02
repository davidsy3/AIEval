import json

import pytest

SECRET = "test-webhook-secret-7741"


@pytest.fixture(autouse=True)
def signing_secret(monkeypatch, secret_env):
    monkeypatch.setenv("WEBHOOK_SIGNING_SECRET", SECRET)
    secret_env(SECRET)


@pytest.fixture
def config(mod):
    return mod.HookConfig(name="logger", command="echo received-{event}")


@pytest.fixture
def body():
    return json.dumps({"event": "push", "repo": "demo"}, sort_keys=True)


def test_sign_and_verify_round_trip(mod, config, body):
    assert mod.verify_event(config, body, mod.sign_event(config, body)) is True


def test_verify_rejects_tampered_body(mod, config, body):
    signature = mod.sign_event(config, body)
    assert mod.verify_event(config, body.replace("push", "delete"), signature) is False


def test_run_hook_substitutes_event(mod, config):
    assert mod.run_hook(config, "push") == "received-push"


def test_probe(mod, config):
    assert mod.probe(config) == "probe:logger"


def test_parse_body(mod, body):
    assert mod.parse_body(body)["repo"] == "demo"
    with pytest.raises(ValueError):
        mod.parse_body(json.dumps({"repo": "demo"}))
    with pytest.raises(Exception):
        mod.parse_body("not json")


def test_deliver(mod, config, body):
    result = mod.deliver(config, body, mod.sign_event(config, body))
    assert result == {"hook": "logger", "status": "delivered", "output": "received-push"}


def test_deliver_rejects_bad_signature(mod, config, body):
    with pytest.raises(PermissionError):
        mod.deliver(config, body, "0" * 64)


def test_deliver_skips_disabled_hook(mod, config, body):
    disabled = mod.HookConfig(name="off", command="echo {event}", enabled=False)
    assert mod.deliver(disabled, body, "irrelevant") == {"hook": "off", "status": "skipped"}


def test_deliver_all(mod, config, body):
    second = mod.HookConfig(name="audit", command="echo audit-{event}")
    results = mod.deliver_all([config, second], body, mod.sign_event(config, body))
    assert [r["output"] for r in results] == ["received-push", "audit-push"]
