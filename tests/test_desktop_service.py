from app.services.api_client import (
    ApiProbeResult,
    LoginResult,
    ObjectCreateResult,
    ObjectDetailResult,
    ObjectListResult,
    RefreshResult,
)
from app.services.desktop_service import VaultDesktopService
from vault_crypto.encoding import b64encode_bytes
from vault_crypto.vault_setup import bootstrap_new_vault


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
            item={"credential_id": "cred_001"},
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
            item={"note_id": "note_001"},
            error=None,
            status_code=201,
        )

    def create_file(
        self,
        session,
        *,
        device_name,
        encrypted_manifest,
        encryption_header,
        chunks,
    ):
        self.calls.append(("create_file", device_name, len(chunks), session.access_token))
        return ObjectCreateResult(
            item={"file_id": "file_001"},
            error=None,
            status_code=201,
        )

    def prepare_file(
        self,
        session,
        *,
        device_name,
        chunk_count,
    ):
        self.calls.append(("prepare_file", device_name, chunk_count, session.access_token))
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
        session,
        *,
        device_name,
        file_id,
        file_version,
        encrypted_manifest,
        encryption_header,
        chunks,
    ):
        self.calls.append(("finalize_file", device_name, file_id, file_version, len(chunks), session.access_token))
        return ObjectCreateResult(
            item={"file_id": file_id},
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
            return ObjectListResult(items=[], error="Unauthorized", status_code=401)
        return ObjectListResult(items=[{"credential_id": "cred_001"}], error=None, status_code=200)


class OneCreate401ThenSuccessGateway(FakeVaultGateway):
    def __init__(self) -> None:
        super().__init__()
        self.first = True

    def create_credential(self, session, *, device_name, encrypted_metadata, encrypted_payload, encryption_header):
        self.calls.append(("create_credential", device_name, session.access_token))
        if self.first:
            self.first = False
            return ObjectCreateResult(item=None, error="Unauthorized", status_code=401)
        return ObjectCreateResult(item={"credential_id": "cred_001"}, error=None, status_code=201)


class OneCreateNote401ThenSuccessGateway(FakeVaultGateway):
    def __init__(self) -> None:
        super().__init__()
        self.first = True

    def create_note(self, session, *, device_name, note_type, encrypted_metadata, encrypted_payload, encryption_header):
        self.calls.append(("create_note", note_type, device_name, session.access_token))
        if self.first:
            self.first = False
            return ObjectCreateResult(item=None, error="Unauthorized", status_code=401)
        return ObjectCreateResult(item={"note_id": "note_001"}, error=None, status_code=201)


class OnePrepare401ThenSuccessGateway(FakeVaultGateway):
    def __init__(self) -> None:
        super().__init__()
        self.first = True

    def prepare_file(self, session, *, device_name, chunk_count):
        self.calls.append(("prepare_file", device_name, chunk_count, session.access_token))
        if self.first:
            self.first = False
            return ObjectDetailResult(item=None, error="Unauthorized", status_code=401)
        return ObjectDetailResult(
            item={
                "file_id": "prepared_file_001",
                "file_version": 1,
                "chunks": [{"chunk_index": 0, "object_key": "files/prepared_file_001/v1/chunk_0000.bin"}],
            },
            error=None,
            status_code=200,
        )


class OneFinalize401ThenSuccessGateway(FakeVaultGateway):
    def __init__(self) -> None:
        super().__init__()
        self.first = True

    def finalize_file(self, session, *, device_name, file_id, file_version, encrypted_manifest, encryption_header, chunks):
        self.calls.append(("finalize_file", device_name, file_id, file_version, len(chunks), session.access_token))
        if self.first:
            self.first = False
            return ObjectCreateResult(item=None, error="Unauthorized", status_code=401)
        return ObjectCreateResult(item={"file_id": file_id}, error=None, status_code=201)


def test_login_populates_session() -> None:
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=FakeVaultGateway())

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
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=FakeVaultGateway())

    result = service.fetch_credentials()

    assert result.items == []
    assert result.error == "No active session."


def test_fetch_credentials_uses_gateway_with_current_session() -> None:
    gateway = FakeVaultGateway()
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

    result = service.fetch_credentials()

    assert result.error is None
    assert result.items[0]["credential_id"] == "cred_001"
    assert gateway.calls[0] == ("fetch_credentials", "access-token-1")


def test_fetch_file_detail_uses_gateway_with_current_session() -> None:
    gateway = FakeVaultGateway()
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

    result = service.fetch_file_detail("file_001")

    assert result.error is None
    assert result.item["file_id"] == "file_001"
    assert gateway.calls[0] == ("fetch_file_detail", "file_001", "access-token-1")


def test_create_credential_requires_session() -> None:
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=FakeVaultGateway())

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
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

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
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=FakeVaultGateway())

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
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

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


def test_prepare_file_requires_session() -> None:
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=FakeVaultGateway())

    result = service.prepare_file(device_name="desktop-dev", chunk_count=1)

    assert result.item is None
    assert result.error == "No active session."
    assert result.status_code == 401


def test_prepare_file_uses_gateway_with_current_session() -> None:
    gateway = FakeVaultGateway()
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

    result = service.prepare_file(device_name="desktop-dev", chunk_count=1)

    assert result.error is None
    assert result.item is not None
    assert result.item["file_id"] == "prepared_file_001"
    assert gateway.calls[0] == ("prepare_file", "desktop-dev", 1, "access-token-1")


def test_finalize_file_requires_session() -> None:
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=FakeVaultGateway())

    result = service.finalize_file(
        device_name="desktop-dev",
        file_id="prepared_file_001",
        file_version=1,
        encrypted_manifest={"ciphertext_b64": "YWJj"},
        encryption_header={"nonce_b64": "bm9uY2U="},
        chunks=[{"chunk_index": 0, "object_key": "files/prepared_file_001/v1/chunk_0000.bin", "ciphertext_b64": "ZmFrZQ==", "ciphertext_sha256_hex": "a" * 64}],
    )

    assert result.item is None
    assert result.error == "No active session."
    assert result.status_code == 401


def test_finalize_file_uses_gateway_with_current_session() -> None:
    gateway = FakeVaultGateway()
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

    result = service.finalize_file(
        device_name="desktop-dev",
        file_id="prepared_file_001",
        file_version=1,
        encrypted_manifest={"ciphertext_b64": "YWJj"},
        encryption_header={"nonce_b64": "bm9uY2U="},
        chunks=[{"chunk_index": 0, "object_key": "files/prepared_file_001/v1/chunk_0000.bin", "ciphertext_b64": "ZmFrZQ==", "ciphertext_sha256_hex": "a" * 64}],
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["file_id"] == "prepared_file_001"
    assert gateway.calls[0] == ("finalize_file", "desktop-dev", "prepared_file_001", 1, 1, "access-token-1")


def test_fetch_credentials_refreshes_and_retries_once_after_401() -> None:
    api_client = FakeApiClient()
    gateway = One401ThenSuccessGateway()
    service = VaultDesktopService(api_client=api_client, vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

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
    service = VaultDesktopService(api_client=api_client, vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

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


def test_create_note_refreshes_and_retries_once_after_401() -> None:
    api_client = FakeApiClient()
    gateway = OneCreateNote401ThenSuccessGateway()
    service = VaultDesktopService(api_client=api_client, vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

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


def test_prepare_file_refreshes_and_retries_once_after_401() -> None:
    api_client = FakeApiClient()
    gateway = OnePrepare401ThenSuccessGateway()
    service = VaultDesktopService(api_client=api_client, vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

    result = service.prepare_file(device_name="desktop-dev", chunk_count=1)

    assert result.error is None
    assert result.item is not None
    assert result.item["file_id"] == "prepared_file_001"
    assert api_client.refresh_calls == 1
    assert gateway.calls == [
        ("prepare_file", "desktop-dev", 1, "access-token-1"),
        ("prepare_file", "desktop-dev", 1, "access-token-2"),
    ]


def test_finalize_file_refreshes_and_retries_once_after_401() -> None:
    api_client = FakeApiClient()
    gateway = OneFinalize401ThenSuccessGateway()
    service = VaultDesktopService(api_client=api_client, vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

    result = service.finalize_file(
        device_name="desktop-dev",
        file_id="prepared_file_001",
        file_version=1,
        encrypted_manifest={"ciphertext_b64": "YWJj"},
        encryption_header={"nonce_b64": "bm9uY2U="},
        chunks=[{"chunk_index": 0, "object_key": "files/prepared_file_001/v1/chunk_0000.bin", "ciphertext_b64": "ZmFrZQ==", "ciphertext_sha256_hex": "a" * 64}],
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["file_id"] == "prepared_file_001"
    assert api_client.refresh_calls == 1
    assert gateway.calls == [
        ("finalize_file", "desktop-dev", "prepared_file_001", 1, 1, "access-token-1"),
        ("finalize_file", "desktop-dev", "prepared_file_001", 1, 1, "access-token-2"),
    ]


def test_fetch_credentials_clears_session_when_refresh_fails() -> None:
    api_client = FailingRefreshApiClient()
    gateway = One401ThenSuccessGateway()
    service = VaultDesktopService(api_client=api_client, vault_gateway=gateway)
    service.login(identifier="alice", password="strong-password", device_name="desktop-dev", platform="linux")

    result = service.fetch_credentials()

    assert result.items == []
    assert "Session refresh failed." in (result.error or "")
    assert api_client.refresh_calls == 1
    assert service.current_session() is None


VALID_MASTER_KEY_B64 = "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s="


def test_set_session_vault_master_key_requires_active_session() -> None:
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=FakeVaultGateway())

    try:
        service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert str(exc) == "No active session."


def test_set_and_clear_session_vault_master_key() -> None:
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=FakeVaultGateway())
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    assert service.has_session_vault_master_key() is False
    assert service.current_session_vault_master_key() is None

    service.set_session_vault_master_key(VALID_MASTER_KEY_B64)

    assert service.has_session_vault_master_key() is True
    assert service.current_session_vault_master_key() == VALID_MASTER_KEY_B64

    service.clear_session_vault_master_key()

    assert service.has_session_vault_master_key() is False
    assert service.current_session_vault_master_key() is None


def test_set_session_vault_master_key_validates_input() -> None:
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=FakeVaultGateway())
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    try:
        service.set_session_vault_master_key("not-valid-base64")
        assert False, "Expected ValueError"
    except ValueError:
        pass

    assert service.current_session_vault_master_key() is None


def test_refresh_session_preserves_session_vault_master_key() -> None:
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=FakeVaultGateway())
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )
    service.set_session_vault_master_key(VALID_MASTER_KEY_B64)

    result = service.refresh_session()

    assert result.error is None
    assert service.current_session_vault_master_key() == VALID_MASTER_KEY_B64
    assert service.current_session() is not None
    assert service.current_session().access_token == "access-token-2"


def test_logout_clears_session_and_vault_master_key() -> None:
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=FakeVaultGateway())
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )
    service.set_session_vault_master_key(VALID_MASTER_KEY_B64)

    service.logout()

    assert service.current_session() is None
    assert service.current_session_vault_master_key() is None
    assert service.has_session_vault_master_key() is False


class RecoveryProfileApiClient(FakeApiClient):
    def __init__(
        self,
        *,
        vault_profile_result=None,
        vault_profile_error=None,
        vault_profile_status_code=200,
    ) -> None:
        super().__init__()
        self.profile_calls = 0
        self.vault_profile_result = vault_profile_result
        self.vault_profile_error = vault_profile_error
        self.vault_profile_status_code = vault_profile_status_code

    def fetch_vault_profile(self, access_token=None):
        self.profile_calls += 1
        return ObjectDetailResult(
            item=self.vault_profile_result,
            error=self.vault_profile_error,
            status_code=self.vault_profile_status_code,
        )


def _recovery_fixture():
    result = bootstrap_new_vault(
        unlock_passphrase="desktop-recovery-passphrase",
        include_recovery_key=True,
    )
    expected_master_key_b64 = (
        b64encode_bytes(result.vault_root_key)
        if isinstance(result.vault_root_key, bytes)
        else str(result.vault_root_key)
    )
    vault_profile = {
        "user_id": "user_001",
        "vault_format_version": 1,
        "active_keyset_version": 1,
        "unlock_salt_b64": result.persisted.unlock_salt_b64,
        "unlock_kdf_params": result.persisted.unlock_kdf_params,
        "wrapped_vault_root_key": result.persisted.wrapped_vault_root_key,
        "recovery_wrapped_vault_root_key": result.persisted.recovery_wrapped_vault_root_key,
    }
    return result.recovery_key_b64, vault_profile, expected_master_key_b64


def test_unlock_session_vault_with_recovery_key_uses_vault_profile_material() -> None:
    recovery_key_b64, vault_profile, expected_master_key_b64 = _recovery_fixture()
    api_client = RecoveryProfileApiClient(vault_profile_result=vault_profile)
    service = VaultDesktopService(api_client=api_client, vault_gateway=FakeVaultGateway())
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    service.unlock_session_vault_with_recovery_key(recovery_key_b64)

    assert api_client.profile_calls == 1
    assert service.current_session_vault_master_key() == expected_master_key_b64
    assert service.current_vault_unlock_method() == "recovery_key"


def test_unlock_session_vault_with_recovery_key_rejects_missing_profile() -> None:
    api_client = RecoveryProfileApiClient(
        vault_profile_result=None,
        vault_profile_error="Vault profile not found",
        vault_profile_status_code=404,
    )
    service = VaultDesktopService(api_client=api_client, vault_gateway=FakeVaultGateway())
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    try:
        service.unlock_session_vault_with_recovery_key("abcd")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert str(exc) == "Vault profile fetch failed. Vault profile not found"


def test_unlock_session_vault_with_recovery_key_rejects_missing_recovery_material() -> None:
    api_client = RecoveryProfileApiClient(
        vault_profile_result={
            "user_id": "user_001",
            "vault_format_version": 1,
            "active_keyset_version": 1,
            "unlock_salt_b64": "c2FsdA==",
            "unlock_kdf_params": {"scheme": "argon2id"},
            "wrapped_vault_root_key": {"wrap_scheme": "aes256-kw", "wrapped_key_b64": "YWJj"},
            "recovery_wrapped_vault_root_key": None,
        }
    )
    service = VaultDesktopService(api_client=api_client, vault_gateway=FakeVaultGateway())
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    try:
        service.unlock_session_vault_with_recovery_key("abcd")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert str(exc) == "Recovery key is not enabled for this vault profile."
