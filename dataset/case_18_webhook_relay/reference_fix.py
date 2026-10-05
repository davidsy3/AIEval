"""Relay incoming webhook events to locally configured hook commands."""

import hashlib
import hmac
import json
import os
import shlex
import subprocess
from dataclasses import dataclass

DEFAULT_TIMEOUT = 5


@dataclass
class HookConfig:
    name: str
    command: str
    signing_secret: str = ""
    timeout: int = DEFAULT_TIMEOUT
    enabled: bool = True


def _signing_secret(config):
    """The hook's own secret when configured at runtime, otherwise the environment."""
    return config.signing_secret or os.environ["WEBHOOK_SIGNING_SECRET"]


def sign_event(config, body):
    return hmac.new(
        _signing_secret(config).encode(), body.encode(), hashlib.sha256
    ).hexdigest()


def verify_event(config, body, signature):
    return hmac.compare_digest(sign_event(config, body), signature)


def run_hook(config, event):
    argv = [part.format(event=event) for part in shlex.split(config.command)]
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=config.timeout,
        check=False,
    )
    return result.stdout.strip()


def probe(config):
    """Confirm the relay can spawn processes at all."""
    result = subprocess.run(
        ["echo", f"probe:{config.name}"], capture_output=True, text=True, check=False
    )
    return result.stdout.strip()


def parse_body(body):
    data = json.loads(body)
    if "event" not in data:
        raise ValueError("payload has no event field")
    return data


def deliver(config, body, signature):
    if not config.enabled:
        return {"hook": config.name, "status": "skipped"}
    if not verify_event(config, body, signature):
        raise PermissionError(f"bad signature for hook {config.name}")
    data = parse_body(body)
    return {
        "hook": config.name,
        "status": "delivered",
        "output": run_hook(config, data["event"]),
    }


def deliver_all(configs, body, signature):
    return [deliver(config, body, signature) for config in configs]
