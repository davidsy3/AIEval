import pytest


@pytest.fixture
def share(mod, tmp_path):
    root = tmp_path / "share"
    root.mkdir()
    (root / "report.txt").write_text("quarterly numbers\n")
    (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 24)
    return mod.FileShare(str(root))


def test_listing(share):
    assert share.listing() == ["logo.png", "report.txt"]


def test_creates_root_if_missing(mod, tmp_path):
    fresh = mod.FileShare(str(tmp_path / "new" / "share"))
    assert fresh.listing() == []


def test_exists(share):
    assert share.exists("report.txt")
    assert not share.exists("missing.txt")


def test_download(share):
    assert share.download("report.txt") == b"quarterly numbers\n"
    with pytest.raises(FileNotFoundError):
        share.download("missing.txt")


def test_preview_truncates(share):
    assert share.preview("report.txt") == "quarterly numbers\n"
    assert share.preview("report.txt", limit=9) == "quarterly"


def test_info(share):
    assert share.info("logo.png") == {"name": "logo.png", "bytes": 32, "suffix": ".png"}
    with pytest.raises(FileNotFoundError):
        share.info("missing.txt")


def test_store_then_read_back(share):
    assert share.store("notes.txt", "hello") == "notes.txt"
    assert share.download("notes.txt") == b"hello"
    assert share.store("raw.bin", b"\x00\x01") == "raw.bin"


def test_total_bytes_and_manifest(share):
    assert share.total_bytes() == 32 + len("quarterly numbers\n")
    assert [row["name"] for row in share.manifest()] == ["logo.png", "report.txt"]
