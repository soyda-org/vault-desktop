from pathlib import Path
from types import SimpleNamespace

from app.core.pin_bootstrap import LocalPinBootstrapStore
from app.services.desktop_service import VaultDesktopService

VALID_MASTER_KEY_B64 = "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s="


class FakeApiClient:
    def __init__(self, *, user_id: str) -> None:
        self.user_id = user_id

    def login(self, payload):
        return SimpleNamespace(
            error=None,
            user_id=self.user_id,
            device_id="device_1",
            session_id="session_1",
            access_token="access-token-1",
            refresh_token="refresh-token-1",
            token_type="bearer",
        )

    def refresh(self, payload):
        return SimpleNamespace(
            error=None,
            user_id=self.user_id,
            device_id="device_1",
            session_id="session_1",
            access_token="access-token-2",
            refresh_token="refresh-token-2",
            token_type="bearer",
            status_code=200,
        )

    def probe(self):
        return SimpleNamespace(
            api_base_url="http://127.0.0.1:8000",
            system_ok=True,
            health_ok=True,
            error=None,
        )


def make_service(tmp_path: Path, *, user_id: str) -> VaultDesktopService:
    return VaultDesktopService(
        api_client=FakeApiClient(user_id=user_id),
        vault_gateway=object(),
        local_pin_bootstrap_store=LocalPinBootstrapStore(
            config_path=tmp_path / "pin_bootstrap.json"
        ),
    )


def login(service: VaultDesktopService, *, identifier: str) -> None:
    result = service.login(
        identifier=identifier,
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )
    assert result.error is None


def test_local_pin_bootstrap_status_current_account(tmp_path: Path) -> None:
    service = make_service(tmp_path, user_id="user_1")
    login(service, identifier="alice")
    service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    service.enroll_local_pin_bootstrap(pin="1234")

    assert service.local_pin_bootstrap_status() == "current_account"
    assert service.local_pin_bootstrap_identifier_hint() == "alice"


def test_local_pin_bootstrap_status_other_account(tmp_path: Path) -> None:
    first = make_service(tmp_path, user_id="user_1")
    login(first, identifier="alice")
    first.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    first.enroll_local_pin_bootstrap(pin="1234")
    first.logout()

    second = make_service(tmp_path, user_id="user_2")
    login(second, identifier="bob")

    assert second.local_pin_bootstrap_status() == "other_account"
    assert second.local_pin_bootstrap_identifier_hint() == "alice"


def test_vault_unlock_method_tracks_pin_and_recovery(tmp_path: Path) -> None:
    service = make_service(tmp_path, user_id="user_1")
    login(service, identifier="alice")

    service.unlock_session_vault_with_recovery_key(VALID_MASTER_KEY_B64)
    assert service.current_vault_unlock_method() == "recovery_key"

    service.enroll_local_pin_bootstrap(pin="1234")
    service.clear_session_vault_master_key()
    assert service.current_vault_unlock_method() is None

    service.unlock_session_vault_with_pin("1234")
    assert service.current_vault_unlock_method() == "pin"
