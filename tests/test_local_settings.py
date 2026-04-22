import json
from pathlib import Path

from app.core import local_settings
from app.core.local_settings import LocalSettingsStore, PersistedUiSettings


def test_load_returns_detected_defaults_when_file_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        local_settings,
        "detect_local_device_defaults",
        lambda: ("workstation-01", "linux"),
    )
    store = LocalSettingsStore(config_path=tmp_path / "settings.json")

    settings = store.load()

    assert settings.api_base_url == "http://127.0.0.1:8000"
    assert settings.identifier == "alice"
    assert settings.device_name == "workstation-01"
    assert settings.platform == "linux"
    assert settings.window_geometry_b64 is None
    assert settings.window_x is None
    assert settings.window_y is None
    assert settings.window_width == 1180
    assert settings.window_height == 780
    assert settings.last_tab_index == 0
    assert settings.theme == "light"
    assert settings.remember_session is False
    assert settings.remembered_session is None
    assert settings.keep_vault_open is False


def test_load_uses_detected_defaults_for_missing_device_fields(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        local_settings,
        "detect_local_device_defaults",
        lambda: ("travel-laptop", "darwin"),
    )
    config_path = tmp_path / "settings.json"
    config_path.write_text(
        json.dumps(
            {
                "api_base_url": "http://127.0.0.1:9000",
                "identifier": "bob",
                "last_tab_index": 1,
                "theme": "dark",
            }
        ),
        encoding="utf-8",
    )

    loaded = LocalSettingsStore(config_path=config_path).load()

    assert loaded.device_name == "travel-laptop"
    assert loaded.platform == "darwin"
    assert loaded.api_base_url == "http://127.0.0.1:9000"
    assert loaded.identifier == "bob"


def test_save_then_load_round_trip(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    store = LocalSettingsStore(config_path=config_path)

    saved = PersistedUiSettings(
        api_base_url="http://127.0.0.1:9000",
        identifier="bob",
        device_name="workstation",
        platform="linux",
        window_geometry_b64="ZmFrZS1nZW9tZXRyeQ==",
        window_x=40,
        window_y=50,
        window_width=960,
        window_height=640,
        last_tab_index=2,
        theme="dark",
        remember_session=True,
        keep_vault_open=True,
        remembered_session={
            "identifier": "bob",
            "user_id": "user-1",
            "device_id": "device-1",
            "session_id": "session-1",
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "token_type": "bearer",
        },
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
            window_geometry_b64=None,
            window_x=None,
            window_y=None,
            window_width=1180,
            window_height=780,
            last_tab_index=0,
        )
    )

    data = json.loads(config_path.read_text(encoding="utf-8"))

    assert "vault_master_key_b64" not in data
    assert "session_vault_key" not in data


def test_load_restores_persisted_remembered_session(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    config_path.write_text(
        json.dumps(
            {
                "remember_session": True,
                "remembered_session": {
                    "identifier": "alice",
                    "user_id": "user-1",
                    "device_id": "device-1",
                    "session_id": "session-1",
                    "access_token": "access-1",
                    "refresh_token": "refresh-1",
                    "token_type": "bearer",
                },
            }
        ),
        encoding="utf-8",
    )

    loaded = LocalSettingsStore(config_path=config_path).load()

    assert loaded.remember_session is True
    assert loaded.keep_vault_open is False
    assert loaded.remembered_session == {
        "identifier": "alice",
        "user_id": "user-1",
        "device_id": "device-1",
        "session_id": "session-1",
        "access_token": "access-1",
        "refresh_token": "refresh-1",
        "token_type": "bearer",
    }


def test_load_restores_keep_vault_open_preference(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    config_path.write_text(
        json.dumps(
            {
                "keep_vault_open": True,
            }
        ),
        encoding="utf-8",
    )

    loaded = LocalSettingsStore(config_path=config_path).load()

    assert loaded.keep_vault_open is True


def test_load_restores_window_size(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    config_path.write_text(
        json.dumps(
            {
                "window_width": 900,
                "window_height": 620,
            }
        ),
        encoding="utf-8",
    )

    loaded = LocalSettingsStore(config_path=config_path).load()

    assert loaded.window_width == 900
    assert loaded.window_height == 620


def test_load_restores_window_position(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    config_path.write_text(
        json.dumps(
            {
                "window_x": 120,
                "window_y": 80,
            }
        ),
        encoding="utf-8",
    )

    loaded = LocalSettingsStore(config_path=config_path).load()

    assert loaded.window_x == 120
    assert loaded.window_y == 80


def test_load_restores_window_geometry_blob(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    config_path.write_text(
        json.dumps(
            {
                "window_geometry_b64": "ZmFrZS1nZW9tZXRyeQ==",
            }
        ),
        encoding="utf-8",
    )

    loaded = LocalSettingsStore(config_path=config_path).load()

    assert loaded.window_geometry_b64 == "ZmFrZS1nZW9tZXRyeQ=="


def test_default_config_path_uses_windows_appdata(monkeypatch) -> None:
    monkeypatch.setattr(
        local_settings,
        "get_local_app_config_dir",
        lambda: Path(r"C:\Users\steve\AppData\Roaming\vault-desktop"),
    )

    store = LocalSettingsStore()

    assert str(store.config_path).replace("/", "\\") == (
        r"C:\Users\steve\AppData\Roaming\vault-desktop\settings.json"
    )


def test_default_config_path_uses_xdg_config_home(monkeypatch) -> None:
    monkeypatch.setattr(
        local_settings,
        "get_local_app_config_dir",
        lambda: Path("/tmp/xdg-config/vault-desktop"),
    )

    store = LocalSettingsStore()

    assert store.config_path == Path("/tmp/xdg-config/vault-desktop/settings.json")
