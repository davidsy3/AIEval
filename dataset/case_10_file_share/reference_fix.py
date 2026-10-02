"""Download helper for a folder of shared files."""

from pathlib import Path

PREVIEW_CHARS = 400


class FileShare:
    """Serves the files kept directly under one share root."""

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _locate(self, name):
        base = self.root.resolve()
        path = (base / name).resolve()
        if path == base or not path.is_relative_to(base):
            raise ValueError(f"{name!r} is outside the share root")
        return path

    def listing(self):
        return sorted(p.name for p in self.root.iterdir() if p.is_file())

    def exists(self, name):
        return self._locate(name).is_file()

    def download(self, name):
        path = self._locate(name)
        if not path.is_file():
            raise FileNotFoundError(name)
        return path.read_bytes()

    def preview(self, name, limit=PREVIEW_CHARS):
        return self.download(name).decode("utf-8", errors="replace")[:limit]

    def info(self, name):
        path = self._locate(name)
        if not path.is_file():
            raise FileNotFoundError(name)
        return {"name": path.name, "bytes": path.stat().st_size, "suffix": path.suffix}

    def store(self, name, data):
        path = self._locate(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            data = data.encode()
        path.write_bytes(data)
        return path.name

    def total_bytes(self):
        return sum(p.stat().st_size for p in self.root.iterdir() if p.is_file())

    def manifest(self):
        return [self.info(name) for name in self.listing()]
