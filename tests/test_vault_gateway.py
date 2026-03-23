from app.core.session import DesktopSession
from app.services.api_client import ObjectCreateResult, ObjectDetailResult, ObjectListResult
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

    def create_credential(
        self,
        *,
        device_name,
        encrypted_metadata,
        encrypted_payload,
        encryption_header,
        access_token=None,
    ):
        self.calls.append(
            (
                "create_credential",
                device_name,
                encrypted_metadata,
                encrypted_payload,
                encryption_header,
                access_token,
            )
        )
        return ObjectCreateResult(
            item={"credential_id": "cred_001"},
            error=None,
            status_code=201,
        )

    def create_note(
        self,
        *,
        device_name,
        note_type,
        encrypted_metadata,
        encrypted_payload,
        encryption_header,
        access_token=None,
    ):
        self.calls.append(
            (
                "create_note",
                device_name,
                note_type,
                encrypted_metadata,
                encrypted_payload,
                encryption_header,
                access_token,
            )
        )
        return ObjectCreateResult(
            item={"note_id": "note_001"},
            error=None,
            status_code=201,
        )

    def create_file(
        self,
        *,
        device_name,
        encrypted_manifest,
        encryption_header,
        chunks,
        access_token=None,
    ):
        self.calls.append(
            (
                "create_file",
                device_name,
                encrypted_manifest,
                encryption_header,
                chunks,
                access_token,
            )
        )
        return ObjectCreateResult(
            item={"file_id": "file_001"},
            error=None,
            status_code=201,
        )


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


def test_authenticated_gateway_create_credential_uses_access_token() -> None:
    api_client = FakeApiClient()
    gateway = AuthenticatedVaultGateway(api_client)

    result = gateway.create_credential(
        make_session(),
        device_name="desktop-dev",
        encrypted_metadata={"ciphertext_b64": "YWJj"},
        encrypted_payload={"ciphertext_b64": "ZGVm"},
        encryption_header={"nonce_b64": "bm9uY2U="},
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["credential_id"] == "cred_001"
    assert api_client.calls[0] == (
        "create_credential",
        "desktop-dev",
        {"ciphertext_b64": "YWJj"},
        {"ciphertext_b64": "ZGVm"},
        {"nonce_b64": "bm9uY2U="},
        "access-token",
    )


def test_authenticated_gateway_create_note_uses_access_token() -> None:
    api_client = FakeApiClient()
    gateway = AuthenticatedVaultGateway(api_client)

    result = gateway.create_note(
        make_session(),
        device_name="desktop-dev",
        note_type="note",
        encrypted_metadata={"ciphertext_b64": "YWJj"},
        encrypted_payload={"ciphertext_b64": "ZGVm"},
        encryption_header={"nonce_b64": "bm9uY2U="},
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["note_id"] == "note_001"
    assert api_client.calls[0] == (
        "create_note",
        "desktop-dev",
        "note",
        {"ciphertext_b64": "YWJj"},
        {"ciphertext_b64": "ZGVm"},
        {"nonce_b64": "bm9uY2U="},
        "access-token",
    )


def test_authenticated_gateway_create_file_uses_access_token() -> None:
    api_client = FakeApiClient()
    gateway = AuthenticatedVaultGateway(api_client)

    result = gateway.create_file(
        make_session(),
        device_name="desktop-dev",
        encrypted_manifest={"ciphertext_b64": "YWJj"},
        encryption_header={"nonce_b64": "bm9uY2U="},
        chunks=[
            {
                "ciphertext_b64": "ZmlsZV9jaHVua19kdW1teQ==",
                "ciphertext_sha256_hex": "df520036f82f6d5c33e0666d8a48e45789fd03dfe3b5f37d663b0faaeeee48b2",
            }
        ],
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["file_id"] == "file_001"
    assert api_client.calls[0] == (
        "create_file",
        "desktop-dev",
        {"ciphertext_b64": "YWJj"},
        {"nonce_b64": "bm9uY2U="},
        [
            {
                "ciphertext_b64": "ZmlsZV9jaHVua19kdW1teQ==",
                "ciphertext_sha256_hex": "df520036f82f6d5c33e0666d8a48e45789fd03dfe3b5f37d663b0faaeeee48b2",
            }
        ],
        "access-token",
    )
