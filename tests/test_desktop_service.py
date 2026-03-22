from app.services.api_client import (
    ApiProbeResult,
    LoginResult,
    ObjectDetailResult,
    ObjectListResult,
)
from app.services.desktop_service import VaultDesktopService


class FakeApiClient:
    def probe(self):
        return ApiProbeResult(
            health_ok=True,
            project_name="vault-api",
            version="0.1.0",
            environment="dev",
            error=None,
        )

    def login(self, payload):
        return LoginResult(
            user_id="user_001",
            device_id="device_001",
            session_id="session_001",
            access_token="access-token",
            refresh_token="refresh-token",
            token_type="bearer",
            error=None,
        )


class FakeVaultGateway:
    def __init__(self) -> None:
        self.calls = []

    def fetch_credentials(self, session):
        self.calls.append(("fetch_credentials", session.identifier))
        return ObjectListResult(
            items=[{"credential_id": "cred_001"}],
            error=None,
        )

    def fetch_notes(self, session):
        self.calls.append(("fetch_notes", session.identifier))
        return ObjectListResult(
            items=[{"note_id": "note_001"}],
            error=None,
        )

    def fetch_files(self, session):
        self.calls.append(("fetch_files", session.identifier))
        return ObjectListResult(
            items=[{"file_id": "file_001"}],
            error=None,
        )

    def fetch_credential_detail(self, session, credential_id):
        self.calls.append(("fetch_credential_detail", session.identifier, credential_id))
        return ObjectDetailResult(
            item={"credential_id": credential_id},
            error=None,
        )

    def fetch_note_detail(self, session, note_id):
        self.calls.append(("fetch_note_detail", session.identifier, note_id))
        return ObjectDetailResult(
            item={"note_id": note_id},
            error=None,
        )

    def fetch_file_detail(self, session, file_id):
        self.calls.append(("fetch_file_detail", session.identifier, file_id))
        return ObjectDetailResult(
            item={"file_id": file_id},
            error=None,
        )


def test_login_populates_session() -> None:
    service = VaultDesktopService(
        api_client=FakeApiClient(),
        vault_gateway=FakeVaultGateway(),
    )

    result = service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    assert result.error is None
    assert service.is_authenticated() is True
    assert service.current_session() is not None
    assert service.current_session().identifier == "alice"


def test_fetch_credentials_requires_session() -> None:
    service = VaultDesktopService(
        api_client=FakeApiClient(),
        vault_gateway=FakeVaultGateway(),
    )

    result = service.fetch_credentials()

    assert result.items == []
    assert result.error == "No active session."


def test_fetch_credentials_uses_gateway_with_current_session() -> None:
    gateway = FakeVaultGateway()
    service = VaultDesktopService(
        api_client=FakeApiClient(),
        vault_gateway=gateway,
    )
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    result = service.fetch_credentials()

    assert result.error is None
    assert result.items[0]["credential_id"] == "cred_001"
    assert gateway.calls[0] == ("fetch_credentials", "alice")


def test_fetch_file_detail_uses_gateway_with_current_session() -> None:
    gateway = FakeVaultGateway()
    service = VaultDesktopService(
        api_client=FakeApiClient(),
        vault_gateway=gateway,
    )
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    result = service.fetch_file_detail("file_001")

    assert result.error is None
    assert result.item["file_id"] == "file_001"
    assert gateway.calls[0] == ("fetch_file_detail", "alice", "file_001")
