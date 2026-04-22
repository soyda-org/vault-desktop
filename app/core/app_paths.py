from __future__ import annotations

import os
from pathlib import Path
import platform as platform_module


def get_local_app_config_dir() -> Path:
    system_name = platform_module.system().strip().lower()

    if system_name == "windows":
        appdata = os.getenv("APPDATA", "").strip()
        if appdata:
            return Path(appdata) / "vault-desktop"
        return Path.home() / "AppData" / "Roaming" / "vault-desktop"

    if system_name == "darwin":
        return Path.home() / "Library" / "Application Support" / "vault-desktop"

    xdg_config_home = os.getenv("XDG_CONFIG_HOME", "").strip()
    if xdg_config_home:
        return Path(xdg_config_home) / "vault-desktop"
    return Path.home() / ".config" / "vault-desktop"

