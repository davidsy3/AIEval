import pytest


@pytest.fixture(autouse=True)
def export_key(monkeypatch, secret_env):
    monkeypatch.setenv("SETTINGS_EXPORT_KEY", "test-export-key-5510")
    secret_env("test-export-key-5510")


@pytest.fixture
def store(mod):
    s = mod.SettingsStore(":memory:")
    s.set("alice", "theme", "dark")
    s.set("alice", "timezone", "Europe/Lisbon")
    s.set("bob", "language", "pt")
    return s


def test_defaults_merged_with_overrides(store):
    assert store.get_all("alice") == {
        "theme": "dark", "language": "en", "timezone": "Europe/Lisbon", "digest": "weekly",
    }
    assert store.get("bob", "theme") == "light"


def test_unknown_key_rejected(store):
    with pytest.raises(KeyError):
        store.set("alice", "font_size", "14")


def test_reset_restores_defaults(mod, store):
    store.reset("alice")
    assert store.get_all("alice") == mod.DEFAULTS


def test_etag_changes_with_settings(store):
    before = store.etag("bob")
    assert before == store.etag("bob")
    store.set("bob", "digest", "daily")
    assert store.etag("bob") != before


def test_export_import_round_trip(mod, store):
    bundle = mod.export_bundle(store, "alice")
    fresh = mod.SettingsStore(":memory:")
    assert mod.import_bundle(fresh, bundle) == "alice"
    assert fresh.get_all("alice") == store.get_all("alice")


def test_tampered_bundle_rejected(mod, store):
    bundle = mod.export_bundle(store, "alice")
    bundle["payload"] = bundle["payload"].replace("dark", "light")
    with pytest.raises(ValueError):
        mod.import_bundle(mod.SettingsStore(":memory:"), bundle)
