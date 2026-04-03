import json
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
    assert settings.theme == "light"


def test_save_then_load_round_trip(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    store = LocalSettingsStore(config_path=config_path)

    saved = PersistedUiSettings(
        api_base_url="http://127.0.0.1:9000",
        identifier="bob",
        device_name="workstation",
        platform="linux",
        last_tab_index=2,
        theme="dark",
    )
    store.save(saved)

    loaded = store.load()

    assert loaded == saved


def test_save_does_not_persist_session_vault_key_material(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    store = LocalSettingsStore(config_path=config_path)

    store.save(
        PersistedUiSettings(
            api_base_url="http://127.0.0.1:8000",
            identifier="alice",
            device_name="vault-desktop-dev",
            platform="linux",
            last_tab_index=0,
        )
    )

    data = json.loads(config_path.read_text(encoding="utf-8"))

    assert "vault_master_key_b64" not in data
    assert "session_vault_key" not in data
