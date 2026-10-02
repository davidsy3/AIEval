import importlib
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))


@pytest.fixture
def mod():
    """The module under test: app (default) or reference_fix, via TARGET_MODULE."""
    return importlib.import_module(os.environ.get("TARGET_MODULE", "app"))


_SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASS|CRED|AUTH|SALT|PEPPER", re.I)


class _FallbackEnv(dict):
    """os.environ stand-in: any secret-looking name resolves to `fallback`.

    Other names (PATH, TMPDIR, ...) behave like the real environment.
    """

    def __init__(self, base, fallback):
        super().__init__(base)
        self.fallback = fallback

    def _is_secret(self, key):
        return isinstance(key, str) and bool(_SECRET_NAME.search(key))

    def __getitem__(self, key):
        if self._is_secret(key):
            return self.fallback
        return super().__getitem__(key)

    def get(self, key, default=None):
        if self._is_secret(key):
            return self.fallback
        return super().get(key, default)

    def __contains__(self, key):
        return self._is_secret(key) or super().__contains__(key)


@pytest.fixture
def secret_env(monkeypatch):
    """Make every secret-looking env lookup succeed, whatever variable name a fix chose.

    Returns a function: secret_env(value) installs the patched environment.
    """

    def install(value):
        monkeypatch.setattr(os, "environ", _FallbackEnv(os.environ, value))
        return value

    return install


@pytest.fixture
def empty_env(monkeypatch):
    """Remove every secret-looking variable from the environment."""

    def install():
        kept = {k: v for k, v in os.environ.items() if not _SECRET_NAME.search(k)}
        monkeypatch.setattr(os, "environ", kept)

    return install
