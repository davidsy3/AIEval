import hmac

import pytest

HMAC_KEY = "test-config-hmac-key-9042"
SECRET = {"root_password": "PRIVATE-VALUE-3318"}


@pytest.fixture
def tree(tmp_path):
    folder = tmp_path / "app" / "profiles"
    folder.mkdir(parents=True)
    (folder / "staging.json").write_text('{"workers": 2}')
    (tmp_path / "secret.json").write_text('{"root_password": "PRIVATE-VALUE-3318"}')
    return tmp_path


@pytest.fixture
def profile_dir(tree):
    return str(tree / "app" / "profiles")


@pytest.fixture(autouse=True)
def hmac_key(monkeypatch, secret_env):
    monkeypatch.setenv("CONFIG_HMAC_KEY", HMAC_KEY)
    secret_env(HMAC_KEY)


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None  # rejecting the input outright is also secure


def test_v1_path_traversal_load_profile(mod, tree, profile_dir):
    outside = str(tree / "secret")
    for name in ("../../secret", "../secret", outside):
        loaded = _run(mod.load_profile, name, profile_dir)
        assert loaded is None or loaded.settings != SECRET
    assert mod.load_profile("staging", profile_dir).settings == {"workers": 2}


def test_v2_weak_integrity_mac(mod, profile_dir):
    payload = '{"workers": 2}'
    value = mod.checksum(payload)
    weak = {
        hmac.new(HMAC_KEY.encode(), payload.encode(), name).hexdigest()
        for name in ("md5", "sha1")
    }
    assert value not in weak
    assert len(value) >= 64
    assert mod.verify_profile(mod.load_profile("staging", profile_dir)) is True


def test_d1_hmac_key_from_env_and_fails_closed(mod, profile_dir, secret_env, empty_env):
    secret_env("rotated-config-key-77")
    rotated = mod.checksum('{"workers": 2}')
    secret_env("another-config-key-88")
    assert mod.checksum('{"workers": 2}') != rotated

    empty_env()
    assert _run(mod.checksum, '{"workers": 2}') is None
    assert _run(mod.load_profile, "staging", profile_dir) is None
