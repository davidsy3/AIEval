"""Thumbnail cache for gallery uploads."""

import hashlib
import hmac
import os
from pathlib import Path

THUMB_WIDTH = 128
CACHE_SUFFIX = ".thumb"


def _gallery_key():
    return os.environ["GALLERY_KEY"]


class ThumbnailCache:
    """Keeps one rendered thumbnail per upload, addressed by a cache key."""

    def __init__(self, base_dir, width=THUMB_WIDTH):
        self.base = Path(base_dir)
        self.uploads = self.base / "uploads"
        self.cache = self.base / "cache"
        self.uploads.mkdir(parents=True, exist_ok=True)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.width = width

    def cache_name(self, name, width=None):
        """Cache-key filename for one upload; MD5 here is an addressing choice."""
        key = f"{name}:{width or self.width}"
        return hashlib.md5(key.encode(), usedforsecurity=False).hexdigest() + CACHE_SUFFIX

    def _source_path(self, name):
        base = self.uploads.resolve()
        path = (base / name).resolve()
        if path == base or not path.is_relative_to(base):
            raise ValueError(f"{name!r} is outside the uploads directory")
        return path

    def _render(self, data, width):
        step = max(1, len(data) // max(1, width))
        return data[::step][:width]

    def build(self, name, width=None):
        data = self._source_path(name).read_bytes()
        width = width or self.width
        target = self.cache / self.cache_name(name, width)
        target.write_bytes(self._render(data, width))
        return target.name

    def get(self, name, width=None):
        width = width or self.width
        cached = self.cache / self.cache_name(name, width)
        if not cached.is_file():
            self.build(name, width)
        return cached.read_bytes()

    def signature(self, name, width=None):
        payload = f"{name}:{width or self.width}"
        return hmac.new(
            _gallery_key().encode(), payload.encode(), hashlib.sha256
        ).hexdigest()

    def signed_url(self, name, width=None):
        return f"/thumbs/{self.cache_name(name, width)}?sig={self.signature(name, width)}"

    def verify_signature(self, name, width, signature):
        return hmac.compare_digest(self.signature(name, width), signature)

    def stored(self):
        return sorted(p.name for p in self.cache.iterdir() if p.suffix == CACHE_SUFFIX)

    def purge(self):
        removed = 0
        for path in self.cache.iterdir():
            if path.suffix == CACHE_SUFFIX:
                path.unlink()
                removed += 1
        return removed
