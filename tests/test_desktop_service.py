from app.services.api_client import (
    ApiProbeResult,
    LoginResult,
    ObjectCreateResult,
    ObjectDetailResult,
    ObjectListResult,
    RefreshResult,
)
from app.services.desktop_service import VaultDesktopService


class FakeApiClient:
    def __init__(self) -> None:
        self.refresh_calls = 0

    def probe(self):
        return ApiProbeResult(
            health_ok=True,
            project_name="vault-api",
            version="0.1.0",
            environment="dev",
            error=None,
            status_code=200,
        )

    def login(self, payload):
        return LoginResult(
            user_id="user_001",
            device_id="device_001",
            session_id="session_001",
            access_token="access-token-1",
            refresh_token="refresh-token-1",
            token_type="bearer",
            error=None,
            status_code=200,
        )

    def refresh(self, payload):
        self.refresh_calls += 1
        return RefreshResult(
            user_id="user_001",
            device_id="device_001",
            session_id="session_001",
            access_token="access-token-2",
            refresh_token="refresh-token-2",
            token_type="bearer",
            error=None,
            status_code=200,
        )


class FailingRefreshApiClient(FakeApiClient):
    def refresh(self, payload):
        self.refresh_calls += 1
        return RefreshResult(
            user_id=None,
            device_id=None,
            session_id=None,
            access_token=None,
            refresh_token=None,
            token_type=None,
            error="Invalid refresh token",
            status_code=401,
        )


class FakeVaultGateway:
    def __init__(self) -> None:
        self.calls = []

    def fetch_credentials(self, session):
        self.calls.append(("fetch_credentials", session.access_token))
        return ObjectListResult(
            items=[{"credential_id": "cred_001"}],
            error=None,
            status_code=200,
        )

    def fetch_notes(self, session):
        self.calls.append(("fetch_notes", session.access_token))
        return ObjectListResult(
            items=[{"note_id": "note_001"}],
            error=None,
            status_code=200,
        )

    def fetch_files(self, session):
        self.calls.append(("fetch_files", session.access_token))
        return ObjectListResult(
            items=[{"file_id": "file_001"}],
            error=None,
            status_code=200,
        )

    def fetch_credential_detail(self, session, credential_id):
        self.calls.append(("fetch_credential_detail", credential_id, session.access_token))
        return ObjectDetailResult(
            item={"credential_id": credential_id},
            error=None,
            status_code=200,
        )

    def fetch_note_detail(self, session, note_id):
        self.calls.append(("fetch_note_detail", note_id, session.access_token))
        return ObjectDetailResult(
            item={"note_id": note_id},
            error=None,
            status_code=200,
        )

    def fetch_file_detail(self, session, file_id):
        self.calls.append(("fetch_file_detail", file_id, session.access_token))
        return ObjectDetailResult(
            item={"file_id": file_id},
            error=None,
            status_code=200,
        )

    def create_credential(
        self,
        session,
        *,
        device_name,
        encrypted_metadata,
        encrypted_payload,
        encryption_header,
    ):
        self.calls.append(("create_credential", device_name, session.access_token))
        return ObjectCreateResult(
            item={
                "credential_id": "cred_001",
                "device_name": device_name,
                "encrypted_metadata": encrypted_metadata,
                "encrypted_payload": encrypted_payload,
                "encryption_header": encryption_header,
            },
            error=None,
            status_code=201,
        )

    def create_note(
        self,
        session,
        *,
        device_name,
        note_type,
        encrypted_metadata,
        encrypted_payload,
        encryption_header,
    ):
        self.calls.append(("create_note", note_type, device_name, session.access_token))
        return ObjectCreateResult(
            item={
                "note_id": "note_001",
                "note_type": note_type,
                "device_name": device_name,
                "encrypted_metadata": encrypted_metadata,
                "encrypted_payload": encrypted_payload,
                "encryption_header": encryption_header,
            },
            error=None,
            status_code=201,
        )


class One401ThenSuccessGateway(FakeVaultGateway):
    def __init__(self) -> None:
        super().__init__()
        self.first = True

    def fetch_credentials(self, session):
        self.calls.append(("fetch_credentials", session.access_token))
        if self.first:
            self.first = False
            return ObjectListResult(
                items=[],
                error="Unauthorized",
                status_code=401,
            )
        return ObjectListResult(
            items=[{"credential_id": "cred_001"}],
            error=None,
            status_code=200,
        )


class OneCreate401ThenSuccessGateway(FakeVaultGateway):
    def __init__(self) -> None:
        super().__init__()
        self.first = True

    def create_credential(
        self,
        session,
        *,
        device_name,
        encrypted_metadata,
        encrypted_payload,
        encryption_header,
    ):
        self.calls.append(("create_credential", device_name, session.access_token))
        if self.first:
            self.first = False
            return ObjectCreateResult(
                item=None,
                error="Unauthorized",
                status_code=401,
            )
        return ObjectCreateResult(
            item={
                "credential_id": "cred_001",
                "device_name": device_name,
            },
            error=None,
            status_code=201,
        )


class OneCreateNote401ThenSuccessGateway(FakeVaultGateway):
    def __init__(self) -> None:
        super().__init__()
        self.first = True

    def create_note(
        self,
        session,
        *,
        device_name,
        note_type,
        encrypted_metadata,
        encrypted_payload,
        encryption_header,
    ):
        self.calls.append(("create_note", note_type, device_name, session.access_token))
        if self.first:
            self.first = False
            return ObjectCreateResult(
                item=None,
                error="Unauthorized",
                status_code=401,
            )
        return ObjectCreateResult(
            item={
                "note_id": "note_001",
                "note_type": note_type,
            },
            error=None,
            status_code=201,
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
    assert service.current_session().refresh_token == "refresh-token-1"


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
    assert gateway.calls[0] == ("fetch_credentials", "access-token-1")


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
    assert gateway.calls[0] == ("fetch_file_detail", "file_001", "access-token-1")


def test_create_credential_requires_session() -> None:
    service = VaultDesktopService(
        api_client=FakeApiClient(),
        vault_gateway=FakeVaultGateway(),
    )

    result = service.create_credential(
        device_name="desktop-dev",
        encrypted_metadata={"ciphertext_b64": "YWJj"},
        encrypted_payload={"ciphertext_b64": "ZGVm"},
        encryption_header={"nonce_b64": "bm9uY2U="},
    )

    assert result.item is None
    assert result.error == "No active session."
    assert result.status_code == 401


def test_create_credential_uses_gateway_with_current_session() -> None:
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

    result = service.create_credential(
        device_name="desktop-dev",
        encrypted_metadata={"ciphertext_b64": "YWJj"},
        encrypted_payload={"ciphertext_b64": "ZGVm"},
        encryption_header={"nonce_b64": "bm9uY2U="},
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["credential_id"] == "cred_001"
    assert gateway.calls[0] == ("create_credential", "desktop-dev", "access-token-1")


def test_create_note_requires_session() -> None:
    service = VaultDesktopService(
        api_client=FakeApiClient(),
        vault_gateway=FakeVaultGateway(),
    )

    result = service.create_note(
        device_name="desktop-dev",
        note_type="note",
        encrypted_metadata={"ciphertext_b64": "YWJj"},
        encrypted_payload={"ciphertext_b64": "ZGVm"},
        encryption_header={"nonce_b64": "bm9uY2U="},
    )

    assert result.item is None
    assert result.error == "No active session."
    assert result.status_code == 401


def test_create_note_uses_gateway_with_current_session() -> None:
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

    result = service.create_note(
        device_name="desktop-dev",
        note_type="note",
        encrypted_metadata={"ciphertext_b64": "YWJj"},
        encrypted_payload={"ciphertext_b64": "ZGVm"},
        encryption_header={"nonce_b64": "bm9uY2U="},
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["note_id"] == "note_001"
    assert gateway.calls[0] == ("create_note", "note", "desktop-dev", "access-token-1")


def test_fetch_credentials_refreshes_and_retries_once_after_401() -> None:
    api_client = FakeApiClient()
    gateway = One401ThenSuccessGateway()
    service = VaultDesktopService(
        api_client=api_client,
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
    assert api_client.refresh_calls == 1
    assert gateway.calls == [
        ("fetch_credentials", "access-token-1"),
        ("fetch_credentials", "access-token-2"),
    ]
    assert service.current_session().access_token == "access-token-2"
    assert service.current_session().refresh_token == "refresh-token-2"


def test_create_credential_refreshes_and_retries_once_after_401() -> None:
    api_client = FakeApiClient()
    gateway = OneCreate401ThenSuccessGateway()
    service = VaultDesktopService(
        api_client=api_client,
        vault_gateway=gateway,
    )
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    result = service.create_credential(
        device_name="desktop-dev",
        encrypted_metadata={"ciphertext_b64": "YWJj"},
        encrypted_payload={"ciphertext_b64": "ZGVm"},
        encryption_header={"nonce_b64": "bm9uY2U="},
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["credential_id"] == "cred_001"
    assert api_client.refresh_calls == 1
    assert gateway.calls == [
        ("create_credential", "desktop-dev", "access-token-1"),
        ("create_credential", "desktop-dev", "access-token-2"),
    ]
    assert service.current_session().access_token == "access-token-2"
    assert service.current_session().refresh_token == "refresh-token-2"


def test_create_note_refreshes_and_retries_once_after_401() -> None:
    api_client = FakeApiClient()
    gateway = OneCreateNote401ThenSuccessGateway()
    service = VaultDesktopService(
        api_client=api_client,
        vault_gateway=gateway,
    )
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    result = service.create_note(
        device_name="desktop-dev",
        note_type="note",
        encrypted_metadata={"ciphertext_b64": "YWJj"},
        encrypted_payload={"ciphertext_b64": "ZGVm"},
        encryption_header={"nonce_b64": "bm9uY2U="},
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["note_id"] == "note_001"
    assert api_client.refresh_calls == 1
    assert gateway.calls == [
        ("create_note", "note", "desktop-dev", "access-token-1"),
        ("create_note", "note", "desktop-dev", "access-token-2"),
    ]
    assert service.current_session().access_token == "access-token-2"
    assert service.current_session().refresh_token == "refresh-token-2"


def test_fetch_credentials_clears_session_when_refresh_fails() -> None:
    api_client = FailingRefreshApiClient()
    gateway = One401ThenSuccessGateway()
    service = VaultDesktopService(
        api_client=api_client,
        vault_gateway=gateway,
    )
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    result = service.fetch_credentials()

    assert result.items == []
    assert "Session refresh failed." in (result.error or "")
    assert api_client.refresh_calls == 1
    assert service.current_session() is None
