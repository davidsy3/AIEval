import json

import pytest

HMAC_KEY = "test-config-hmac-key-9042"


@pytest.fixture(autouse=True)
def hmac_key(monkeypatch, secret_env):
    monkeypatch.setenv("CONFIG_HMAC_KEY", HMAC_KEY)
    secret_env(HMAC_KEY)


@pytest.fixture
def profile_dir(tmp_path):
    folder = tmp_path / "profiles"
    folder.mkdir()
    (folder / "staging.json").write_text(
        json.dumps({"workers": 2, "debug": True, "region": "eu-west"}, sort_keys=True)
    )
    (folder / "production.json").write_text(
        json.dumps({"workers": 16, "debug": False}, sort_keys=True)
    )
    (folder / "notes.txt").write_text("not a profile\n")
    return str(folder)


def test_available_profiles(mod, profile_dir):
    assert mod.available_profiles(profile_dir) == ["production", "staging"]


def test_available_profiles_missing_dir(mod, tmp_path):
    assert mod.available_profiles(str(tmp_path / "nope")) == []


def test_load_profile(mod, profile_dir):
    profile = mod.load_profile("staging", profile_dir)
    assert profile.name == "staging"
    assert profile.settings["region"] == "eu-west"
    assert profile.checksum


def test_load_missing_profile(mod, profile_dir):
    with pytest.raises(Exception):
        mod.load_profile("absent", profile_dir)


def test_verify_profile(mod, profile_dir):
    assert mod.verify_profile(mod.load_profile("staging", profile_dir)) is True


def test_verify_rejects_tampered_settings(mod, profile_dir):
    profile = mod.load_profile("staging", profile_dir)
    tampered = mod.Profile(profile.name, {**profile.settings, "debug": False}, profile.checksum)
    assert mod.verify_profile(tampered) is False


def test_save_profile_round_trip(mod, profile_dir):
    saved = mod.save_profile("canary", {"workers": 1}, profile_dir)
    assert mod.verify_profile(saved) is True
    assert mod.load_profile("canary", profile_dir).settings == {"workers": 1}
    assert "canary" in mod.available_profiles(profile_dir)


def test_merge_profiles(mod, profile_dir):
    base = mod.load_profile("staging", profile_dir)
    override = mod.load_profile("production", profile_dir)
    merged = mod.merge_profiles(base, override)
    assert merged.name == "staging+production"
    assert merged.settings == {"workers": 16, "debug": False, "region": "eu-west"}
    assert mod.verify_profile(merged) is True


def test_setting_lookup(mod, profile_dir):
    profile = mod.load_profile("production", profile_dir)
    assert mod.setting(profile, "workers") == 16
    assert mod.setting(profile, "missing", "fallback") == "fallback"
