from app.core.session import DesktopSession
from app.services.api_client import ObjectDetailResult, ObjectListResult
from app.services.vault_gateway import AuthenticatedVaultGateway


class FakeApiClient:
    def __init__(self) -> None:
        self.calls = []

    def fetch_credentials(self, access_token=None):
        self.calls.append(("fetch_credentials", access_token))
        return ObjectListResult(items=[{"credential_id": "cred_001"}], error=None, status_code=200)

    def fetch_notes(self, access_token=None):
        self.calls.append(("fetch_notes", access_token))
        return ObjectListResult(items=[{"note_id": "note_001"}], error=None, status_code=200)

    def fetch_files(self, access_token=None):
        self.calls.append(("fetch_files", access_token))
        return ObjectListResult(items=[{"file_id": "file_001"}], error=None, status_code=200)

    def fetch_credential_detail(self, credential_id, access_token=None):
        self.calls.append(("fetch_credential_detail", credential_id, access_token))
        return ObjectDetailResult(item={"credential_id": credential_id}, error=None, status_code=200)

    def fetch_note_detail(self, note_id, access_token=None):
        self.calls.append(("fetch_note_detail", note_id, access_token))
        return ObjectDetailResult(item={"note_id": note_id}, error=None, status_code=200)

    def fetch_file_detail(self, file_id, access_token=None):
        self.calls.append(("fetch_file_detail", file_id, access_token))
        return ObjectDetailResult(item={"file_id": file_id}, error=None, status_code=200)


def make_session() -> DesktopSession:
    return DesktopSession(
        identifier="alice",
        user_id="user_001",
        device_id="device_001",
        session_id="session_001",
        access_token="access-token",
        refresh_token="refresh-token",
        token_type="bearer",
    )


def test_authenticated_gateway_fetch_credentials_uses_access_token() -> None:
    api_client = FakeApiClient()
    gateway = AuthenticatedVaultGateway(api_client)

    result = gateway.fetch_credentials(make_session())

    assert result.error is None
    assert result.items[0]["credential_id"] == "cred_001"
    assert api_client.calls[0] == ("fetch_credentials", "access-token")


def test_authenticated_gateway_fetch_notes_uses_access_token() -> None:
    api_client = FakeApiClient()
    gateway = AuthenticatedVaultGateway(api_client)

    result = gateway.fetch_notes(make_session())

    assert result.error is None
    assert result.items[0]["note_id"] == "note_001"
    assert api_client.calls[0] == ("fetch_notes", "access-token")


def test_authenticated_gateway_fetch_file_detail_uses_access_token() -> None:
    api_client = FakeApiClient()
    gateway = AuthenticatedVaultGateway(api_client)

    result = gateway.fetch_file_detail(make_session(), "file_001")

    assert result.error is None
    assert result.item["file_id"] == "file_001"
    assert api_client.calls[0] == (
        "fetch_file_detail",
        "file_001",
        "access-token",
    )


def test_authenticated_gateway_fetch_credential_detail_uses_access_token() -> None:
    api_client = FakeApiClient()
    gateway = AuthenticatedVaultGateway(api_client)

    result = gateway.fetch_credential_detail(make_session(), "cred_001")

    assert result.error is None
    assert result.item["credential_id"] == "cred_001"
    assert api_client.calls[0] == (
        "fetch_credential_detail",
        "cred_001",
        "access-token",
    )
