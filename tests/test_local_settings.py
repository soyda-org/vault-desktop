from pathlib import Path

from app.core.local_settings import LocalSettingsStore, PersistedUiSettings


def test_load_returns_defaults_when_file_missing(tmp_path: Path) -> None:
    store = LocalSettingsStore(config_path=tmp_path / "settings.json")

    settings = store.load()

    assert settings.api_base_url == "http://127.0.0.1:8000"
    assert settings.identifier == "alice"
    assert settings.device_name == "vault-desktop-dev"
    assert settings.platform == "linux"
    assert settings.last_tab_index == 0


def test_save_then_load_round_trip(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    store = LocalSettingsStore(config_path=config_path)

    saved = PersistedUiSettings(
        api_base_url="http://127.0.0.1:9000",
        identifier="bob",
        device_name="workstation",
        platform="linux",
        last_tab_index=2,
    )
    store.save(saved)

    loaded = store.load()

    assert loaded == saved
