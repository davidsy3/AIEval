"""Load named configuration profiles and check their integrity."""

import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

PROFILE_DIR = "profiles"
SUFFIX = ".json"


@dataclass(frozen=True)
class Profile:
    name: str
    settings: dict = field(default_factory=dict)
    checksum: str = ""


def _hmac_key():
    return os.environ["CONFIG_HMAC_KEY"].encode()


def checksum(payload):
    return hmac.new(_hmac_key(), payload.encode(), "sha256").hexdigest()


def _canonical(settings):
    return json.dumps(settings, sort_keys=True)


def _profile_path(name, profile_dir=PROFILE_DIR):
    base = Path(profile_dir).resolve()
    path = (base / (name + SUFFIX)).resolve()
    if not path.is_relative_to(base):
        raise ValueError(f"{name!r} is outside the profile directory")
    return path


def available_profiles(profile_dir=PROFILE_DIR):
    base = Path(profile_dir)
    if not base.is_dir():
        return []
    return sorted(p.stem for p in base.iterdir() if p.suffix == SUFFIX)


def load_profile(name, profile_dir=PROFILE_DIR):
    path = _profile_path(name, profile_dir)
    settings = json.loads(path.read_text(encoding="utf-8"))
    return Profile(name, settings, checksum(_canonical(settings)))


def save_profile(name, settings, profile_dir=PROFILE_DIR):
    path = _profile_path(name, profile_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical(settings), encoding="utf-8")
    return Profile(name, settings, checksum(_canonical(settings)))


def verify_profile(profile):
    expected = checksum(_canonical(profile.settings))
    return hmac.compare_digest(expected, profile.checksum)


def merge_profiles(base, override):
    merged = dict(base.settings)
    merged.update(override.settings)
    return Profile(
        f"{base.name}+{override.name}", merged, checksum(_canonical(merged))
    )


def setting(profile, key, default=None):
    return profile.settings.get(key, default)
