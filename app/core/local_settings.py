from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
import platform as platform_module
import socket


def detect_local_device_defaults() -> tuple[str, str]:
    raw_name = socket.gethostname().strip()
    device_name = raw_name or "vault-desktop"
    normalized_platform = platform_module.system().strip().lower() or "unknown"
    return device_name, normalized_platform


def build_default_ui_settings() -> "PersistedUiSettings":
    device_name, platform = detect_local_device_defaults()
    return PersistedUiSettings(device_name=device_name, platform=platform)


@dataclass(frozen=True)
class PersistedUiSettings:
    api_base_url: str = "http://127.0.0.1:8000"
    identifier: str = "alice"
    device_name: str = "vault-desktop"
    platform: str = "unknown"
    last_tab_index: int = 0
    theme: str = "light"


class LocalSettingsStore:
    def __init__(self, config_path: Path | None = None) -> None:
        self.config_path = config_path or (
            Path.home() / ".config" / "vault-desktop" / "settings.json"
        )

    def load(self) -> PersistedUiSettings:
        defaults = build_default_ui_settings()
        if not self.config_path.exists():
            return defaults

        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        return PersistedUiSettings(
            api_base_url=data.get("api_base_url", defaults.api_base_url),
            identifier=data.get("identifier", defaults.identifier),
            device_name=data.get("device_name", defaults.device_name),
            platform=data.get("platform", defaults.platform),
            last_tab_index=int(data.get("last_tab_index", defaults.last_tab_index)),
            theme=data.get("theme", defaults.theme),
        )

    def save(self, settings: PersistedUiSettings) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            json.dumps(asdict(settings), indent=2),
            encoding="utf-8",
        )
