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
        plaintext_app_name=None,
        plaintext_username=None,
        encrypted_metadata,
        encrypted_payload,
        encryption_header,
        access_token=None,
    ):
        self.calls.append(
            (
                "create_credential",
                device_name,
                plaintext_app_name,
                plaintext_username,
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
        plaintext_title=None,
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
                plaintext_title,
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
        plaintext_filename,
        plaintext_size_bytes,
        encrypted_manifest,
        encryption_header,
        chunks,
        access_token=None,
    ):
        self.calls.append(
            (
                "create_file",
                device_name,
                plaintext_filename,
                plaintext_size_bytes,
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

    def prepare_file(
        self,
        *,
        device_name,
        chunk_count,
        access_token=None,
    ):
        self.calls.append(
            (
                "prepare_file",
                device_name,
                chunk_count,
                access_token,
            )
        )
        return ObjectDetailResult(
            item={
                "file_id": "prepared_file_001",
                "file_version": 1,
                "chunks": [{"chunk_index": 0, "object_key": "files/prepared_file_001/v1/chunk_0000.bin"}],
            },
            error=None,
            status_code=200,
        )

    def finalize_file(
        self,
        *,
        device_name,
        file_id,
        file_version,
        plaintext_filename,
        plaintext_size_bytes,
        encrypted_manifest,
        encryption_header,
        chunks,
        access_token=None,
    ):
        self.calls.append(
            (
                "finalize_file",
                device_name,
                file_id,
                file_version,
                plaintext_filename,
                plaintext_size_bytes,
                encrypted_manifest,
                encryption_header,
                chunks,
                access_token,
            )
        )
        return ObjectCreateResult(
            item={"file_id": file_id},
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
        plaintext_app_name="Personal",
        plaintext_username="alice",
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
        "Personal",
        "alice",
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
        plaintext_title="todo",
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
        "todo",
        {"ciphertext_b64": "YWJj"},
        {"ciphertext_b64": "ZGVm"},
        {"nonce_b64": "bm9uY2U="},
        "access-token",
    )


def test_authenticated_gateway_prepare_file_uses_access_token() -> None:
    api_client = FakeApiClient()
    gateway = AuthenticatedVaultGateway(api_client)

    result = gateway.prepare_file(
        make_session(),
        device_name="desktop-dev",
        chunk_count=1,
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["file_id"] == "prepared_file_001"
    assert api_client.calls[0] == (
        "prepare_file",
        "desktop-dev",
        1,
        "access-token",
    )


def test_authenticated_gateway_finalize_file_uses_access_token() -> None:
    api_client = FakeApiClient()
    gateway = AuthenticatedVaultGateway(api_client)

    result = gateway.finalize_file(
        make_session(),
        device_name="desktop-dev",
        file_id="prepared_file_001",
        file_version=1,
        plaintext_filename="sample.bin",
        plaintext_size_bytes=16,
        encrypted_manifest={"ciphertext_b64": "YWJj"},
        encryption_header={"nonce_b64": "bm9uY2U="},
        chunks=[
            {
                "chunk_index": 0,
                "object_key": "files/prepared_file_001/v1/chunk_0000.bin",
                "ciphertext_b64": "ZmFrZQ==",
                "ciphertext_sha256_hex": "a" * 64,
            }
        ],
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["file_id"] == "prepared_file_001"
    assert api_client.calls[0] == (
        "finalize_file",
        "desktop-dev",
        "prepared_file_001",
        1,
        "sample.bin",
        16,
        {"ciphertext_b64": "YWJj"},
        {"nonce_b64": "bm9uY2U="},
        [
            {
                "chunk_index": 0,
                "object_key": "files/prepared_file_001/v1/chunk_0000.bin",
                "ciphertext_b64": "ZmFrZQ==",
                "ciphertext_sha256_hex": "a" * 64,
            }
        ],
        "access-token",
    )
