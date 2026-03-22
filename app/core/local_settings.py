from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class PersistedUiSettings:
    api_base_url: str = "http://127.0.0.1:8000"
    identifier: str = "alice"
    device_name: str = "vault-desktop-dev"
    platform: str = "linux"
    last_tab_index: int = 0


class LocalSettingsStore:
    def __init__(self, config_path: Path | None = None) -> None:
        self.config_path = config_path or (
            Path.home() / ".config" / "vault-desktop" / "settings.json"
        )

    def load(self) -> PersistedUiSettings:
        if not self.config_path.exists():
            return PersistedUiSettings()

        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        return PersistedUiSettings(
            api_base_url=data.get("api_base_url", "http://127.0.0.1:8000"),
            identifier=data.get("identifier", "alice"),
            device_name=data.get("device_name", "vault-desktop-dev"),
            platform=data.get("platform", "linux"),
            last_tab_index=int(data.get("last_tab_index", 0)),
        )

    def save(self, settings: PersistedUiSettings) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            json.dumps(asdict(settings), indent=2),
            encoding="utf-8",
        )
