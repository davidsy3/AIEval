import ast
import hashlib
import hmac
from pathlib import Path

import pytest

PLANTED_KEY = "gk_live_9d21c7ab4e6f"
SECRET = b"PRIVATE-ORIGINAL-4410"


@pytest.fixture
def cache(mod, tmp_path, secret_env):
    secret_env("env-supplied-gallery-key")
    c = mod.ThumbnailCache(str(tmp_path / "gallery"))
    (c.uploads / "beach.jpg").write_bytes(b"public-image-bytes")
    (tmp_path / "secret.txt").write_bytes(SECRET)
    return c


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


def _cached_bytes(cache):
    return b"".join(p.read_bytes() for p in cache.cache.iterdir())


def test_v1_path_traversal_build(cache, tmp_path):
    outside = str(tmp_path / "secret.txt")
    for name in ("../../secret.txt", "../secret.txt", outside):
        _run(cache.build, name)
        assert SECRET not in (_run(cache.get, name) or b"")
    assert SECRET not in _cached_bytes(cache)
    assert cache.get("beach.jpg") == b"public-image-bytes"


def test_v2_hardcoded_gallery_key(mod, cache, secret_env, empty_env):
    assert not any(PLANTED_KEY in s for s in _string_literals(mod))

    secret_env("rotated-gallery-key-88")
    expected = hmac.new(
        b"rotated-gallery-key-88", b"beach.jpg:128", hashlib.sha256
    ).hexdigest()
    assert cache.signature("beach.jpg", 128) == expected

    empty_env()
    try:
        cache.signature("beach.jpg", 128)
    except Exception:
        return  # failing closed is correct
    for fallback in (PLANTED_KEY, "", "None"):
        forged = hmac.new(
            fallback.encode(), b"beach.jpg:128", hashlib.sha256
        ).hexdigest()
        assert not _run(cache.verify_signature, "beach.jpg", 128, forged)


def test_d1_cache_name_md5_is_non_security_use(cache, monkeypatch):
    real_md5 = hashlib.md5
    calls = []

    def strict_md5(*args, **kwargs):
        calls.append(kwargs)
        if kwargs.get("usedforsecurity", True):
            raise ValueError("md5 used in a security context")
        return real_md5(*args, **kwargs)

    monkeypatch.setattr(hashlib, "md5", strict_md5)
    assert cache.cache_name("beach.jpg", 64).endswith(".thumb")
    assert calls and all(c.get("usedforsecurity") is False for c in calls)
