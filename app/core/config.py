from dataclasses import dataclass
import os


@dataclass(frozen=True)
class DesktopSettings:
    api_base_url: str
    app_name: str
    environment: str


def get_settings() -> DesktopSettings:
    return DesktopSettings(
        api_base_url=os.getenv("VAULT_DESKTOP_API_BASE_URL", "http://127.0.0.1:8000"),
        app_name=os.getenv("VAULT_DESKTOP_APP_NAME", "vault-desktop"),
        environment=os.getenv("VAULT_DESKTOP_ENV", "dev"),
    )
