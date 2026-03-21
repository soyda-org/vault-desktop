from app.core.config import get_settings


def test_get_settings_reads_environment(monkeypatch) -> None:
    monkeypatch.setenv("VAULT_DESKTOP_API_BASE_URL", "http://127.0.0.1:9999")
    monkeypatch.setenv("VAULT_DESKTOP_APP_NAME", "vault-desktop-test")
    monkeypatch.setenv("VAULT_DESKTOP_ENV", "test")

    settings = get_settings()

    assert settings.api_base_url == "http://127.0.0.1:9999"
    assert settings.app_name == "vault-desktop-test"
    assert settings.environment == "test"
