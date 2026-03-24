import httpx

from app.core.session import DesktopSession
from app.services.api_client import (
    LoginResult,
    ObjectCreateResult,
    RefreshResult,
    VaultApiClient,
)
from app.services.desktop_service import VaultDesktopService
from app.services.vault_gateway import AuthenticatedVaultGateway


class FakeResponse:
    def __init__(self, status_code: int, json_data: dict, text: str = "") -> None:
        self.status_code = status_code
        self._json_data = json_data
        self.text = text or str(json_data)

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://test")
            response = httpx.Response(self.status_code, request=request, json=self._json_data)
            raise httpx.HTTPStatusError("boom", request=request, response=response)


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


def test_api_client_delete_credential_posts_authenticated_payload(monkeypatch) -> None:
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return FakeResponse(
            200,
            {
                "credential_id": "cred_001",
                "user_id": "user_001",
                "state": "deleted",
                "current_version": 2,
                "encrypted_metadata": {"ciphertext_b64": "YWJj"},
                "encrypted_payload": {"ciphertext_b64": "ZGVm"},
                "encryption_header": {"nonce_b64": "bm9uY2U="},
                "created_by_device_id": "device_001",
                "created_at": "2030-01-01T00:00:00Z",
            },
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.delete_credential(
        credential_id="cred_001",
        access_token="access-token",
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["credential_id"] == "cred_001"
    assert result.item["state"] == "deleted"
    assert captured["url"] == "http://127.0.0.1:8000/api/v1/vault/credentials/cred_001/delete"
    assert captured["headers"]["Authorization"] == "Bearer access-token"
    assert captured["json"] == {}


def test_api_client_delete_note_posts_authenticated_payload(monkeypatch) -> None:
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return FakeResponse(
            200,
            {
                "note_id": "note_001",
                "user_id": "user_001",
                "note_type": "note",
                "state": "deleted",
                "current_version": 3,
                "encrypted_metadata": None,
                "encrypted_payload": {"ciphertext_b64": "ZGVm"},
                "encryption_header": {"nonce_b64": "bm9uY2U="},
                "created_by_device_id": "device_001",
                "created_at": "2030-01-01T00:00:00Z",
            },
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.delete_note(
        note_id="note_001",
        access_token="access-token",
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["note_id"] == "note_001"
    assert result.item["state"] == "deleted"
    assert captured["url"] == "http://127.0.0.1:8000/api/v1/vault/notes/note_001/delete"
    assert captured["headers"]["Authorization"] == "Bearer access-token"
    assert captured["json"] == {}


class FakeGatewayApiClient:
    def __init__(self) -> None:
        self.calls = []

    def delete_credential(self, *, credential_id, access_token=None):
        self.calls.append(("delete_credential", credential_id, access_token))
        return ObjectCreateResult(
            item={"credential_id": credential_id, "state": "deleted"},
            error=None,
            status_code=200,
        )

    def delete_note(self, *, note_id, access_token=None):
        self.calls.append(("delete_note", note_id, access_token))
        return ObjectCreateResult(
            item={"note_id": note_id, "state": "deleted"},
            error=None,
            status_code=200,
        )


def test_authenticated_gateway_delete_credential_uses_access_token() -> None:
    api_client = FakeGatewayApiClient()
    gateway = AuthenticatedVaultGateway(api_client)

    result = gateway.delete_credential(
        make_session(),
        credential_id="cred_001",
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["credential_id"] == "cred_001"
    assert api_client.calls[0] == ("delete_credential", "cred_001", "access-token")


def test_authenticated_gateway_delete_note_uses_access_token() -> None:
    api_client = FakeGatewayApiClient()
    gateway = AuthenticatedVaultGateway(api_client)

    result = gateway.delete_note(
        make_session(),
        note_id="note_001",
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["note_id"] == "note_001"
    assert api_client.calls[0] == ("delete_note", "note_001", "access-token")


class FakeDesktopApiClient:
    def __init__(self) -> None:
        self.refresh_calls = 0

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

    def probe(self):
        raise NotImplementedError


class FakeDeleteGateway:
    def __init__(self) -> None:
        self.calls = []

    def delete_credential(self, session, *, credential_id):
        self.calls.append(("delete_credential", credential_id, session.access_token))
        return ObjectCreateResult(
            item={"credential_id": credential_id, "state": "deleted"},
            error=None,
            status_code=200,
        )

    def delete_note(self, session, *, note_id):
        self.calls.append(("delete_note", note_id, session.access_token))
        return ObjectCreateResult(
            item={"note_id": note_id, "state": "deleted"},
            error=None,
            status_code=200,
        )


class OneDeleteCredential401ThenSuccessGateway(FakeDeleteGateway):
    def __init__(self) -> None:
        super().__init__()
        self.first = True

    def delete_credential(self, session, *, credential_id):
        self.calls.append(("delete_credential", credential_id, session.access_token))
        if self.first:
            self.first = False
            return ObjectCreateResult(item=None, error="Unauthorized", status_code=401)
        return ObjectCreateResult(
            item={"credential_id": credential_id, "state": "deleted"},
            error=None,
            status_code=200,
        )


class OneDeleteNote401ThenSuccessGateway(FakeDeleteGateway):
    def __init__(self) -> None:
        super().__init__()
        self.first = True

    def delete_note(self, session, *, note_id):
        self.calls.append(("delete_note", note_id, session.access_token))
        if self.first:
            self.first = False
            return ObjectCreateResult(item=None, error="Unauthorized", status_code=401)
        return ObjectCreateResult(
            item={"note_id": note_id, "state": "deleted"},
            error=None,
            status_code=200,
        )


def test_desktop_service_delete_credential_requires_session() -> None:
    service = VaultDesktopService(api_client=FakeDesktopApiClient(), vault_gateway=FakeDeleteGateway())

    result = service.delete_credential(credential_id="cred_001")

    assert result.item is None
    assert result.error == "No active session."
    assert result.status_code == 401


def test_desktop_service_delete_credential_uses_gateway_with_current_session() -> None:
    gateway = FakeDeleteGateway()
    service = VaultDesktopService(api_client=FakeDesktopApiClient(), vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

    result = service.delete_credential(credential_id="cred_001")

    assert result.error is None
    assert result.item is not None
    assert result.item["credential_id"] == "cred_001"
    assert gateway.calls[0] == ("delete_credential", "cred_001", "access-token-1")


def test_desktop_service_delete_credential_refreshes_and_retries_once_after_401() -> None:
    gateway = OneDeleteCredential401ThenSuccessGateway()
    api_client = FakeDesktopApiClient()
    service = VaultDesktopService(api_client=api_client, vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

    result = service.delete_credential(credential_id="cred_001")

    assert result.error is None
    assert api_client.refresh_calls == 1
    assert gateway.calls == [
        ("delete_credential", "cred_001", "access-token-1"),
        ("delete_credential", "cred_001", "access-token-2"),
    ]


def test_desktop_service_delete_note_uses_gateway_with_current_session() -> None:
    gateway = FakeDeleteGateway()
    service = VaultDesktopService(api_client=FakeDesktopApiClient(), vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

    result = service.delete_note(note_id="note_001")

    assert result.error is None
    assert result.item is not None
    assert result.item["note_id"] == "note_001"
    assert gateway.calls[0] == ("delete_note", "note_001", "access-token-1")


def test_desktop_service_delete_note_refreshes_and_retries_once_after_401() -> None:
    gateway = OneDeleteNote401ThenSuccessGateway()
    api_client = FakeDesktopApiClient()
    service = VaultDesktopService(api_client=api_client, vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

    result = service.delete_note(note_id="note_001")

    assert result.error is None
    assert api_client.refresh_calls == 1
    assert gateway.calls == [
        ("delete_note", "note_001", "access-token-1"),
        ("delete_note", "note_001", "access-token-2"),
    ]
