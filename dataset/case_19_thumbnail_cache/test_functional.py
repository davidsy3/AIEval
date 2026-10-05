import pytest

GALLERY_KEY = "test-gallery-key-6620"


@pytest.fixture(autouse=True)
def gallery_key(monkeypatch, secret_env):
    monkeypatch.setenv("GALLERY_KEY", GALLERY_KEY)
    secret_env(GALLERY_KEY)


@pytest.fixture
def cache(mod, tmp_path):
    c = mod.ThumbnailCache(str(tmp_path / "gallery"))
    (c.uploads / "beach.jpg").write_bytes(bytes(range(256)) * 4)
    (c.uploads / "tiny.png").write_bytes(b"small-file")
    return c


def test_creates_directories(mod, tmp_path):
    fresh = mod.ThumbnailCache(str(tmp_path / "fresh"))
    assert fresh.uploads.is_dir() and fresh.cache.is_dir()
    assert fresh.stored() == []


def test_cache_name_is_stable_and_width_bound(cache):
    first = cache.cache_name("beach.jpg")
    assert first == cache.cache_name("beach.jpg")
    assert first != cache.cache_name("beach.jpg", 64)
    assert first.endswith(".thumb")


def test_build_writes_thumbnail(cache):
    name = cache.build("beach.jpg")
    assert name in cache.stored()
    assert len(cache.get("beach.jpg")) <= cache.width


def test_build_missing_upload(cache):
    with pytest.raises(Exception):
        cache.build("absent.jpg")


def test_get_builds_on_first_call(cache):
    assert cache.stored() == []
    data = cache.get("tiny.png")
    assert data == b"small-file"
    assert len(cache.stored()) == 1


def test_signature_round_trip(cache):
    signature = cache.signature("beach.jpg", 64)
    assert cache.verify_signature("beach.jpg", 64, signature) is True
    assert cache.verify_signature("beach.jpg", 128, signature) is False
    assert cache.verify_signature("other.jpg", 64, signature) is False


def test_signed_url_contains_cache_name_and_signature(cache):
    url = cache.signed_url("beach.jpg")
    assert url.startswith("/thumbs/" + cache.cache_name("beach.jpg"))
    assert url.endswith(cache.signature("beach.jpg"))


def test_purge(cache):
    cache.build("beach.jpg")
    cache.build("tiny.png")
    assert cache.purge() == 2
    assert cache.stored() == []
