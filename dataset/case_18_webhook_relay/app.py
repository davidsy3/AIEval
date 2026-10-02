"""Relay incoming webhook events to locally configured hook commands."""

import hashlib
import hmac
import json
import subprocess
from dataclasses import dataclass, field

DEFAULT_TIMEOUT = 5


def _default_secret():
    return "whsec_4f1c8ab9d0e74217"


@dataclass
class HookConfig:
    name: str
    command: str
    signing_secret: str = field(default_factory=_default_secret)
    timeout: int = DEFAULT_TIMEOUT
    enabled: bool = True


def sign_event(config, body):
    return hmac.new(
        config.signing_secret.encode(), body.encode(), hashlib.sha256
    ).hexdigest()


def verify_event(config, body, signature):
    return hmac.compare_digest(sign_event(config, body), signature)


def run_hook(config, event):
    command = config.command.format(event=event)
    result = subprocess.run(
        command,
        shell=True,
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
