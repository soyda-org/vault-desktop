from __future__ import annotations

from collections.abc import Callable

from app.core.session import DesktopSession, SessionStore
from app.services.api_client import (
    ApiProbeResult,
    LoginPayload,
    LoginResult,
    ObjectCreateResult,
    ObjectDetailResult,
    ObjectListResult,
    RefreshPayload,
    RefreshResult,
    VaultApiClient,
)
from app.services.file_crypto_bridge import parse_dev_aes256_key_b64
from app.services.vault_gateway import AuthenticatedVaultGateway, VaultGateway


class VaultDesktopService:
    def __init__(
        self,
        api_client: VaultApiClient,
        vault_gateway: VaultGateway | None = None,
        session_store: SessionStore | None = None,
    ) -> None:
        self.api_client = api_client
        self.session_store = session_store or SessionStore()
        self.vault_gateway = vault_gateway or AuthenticatedVaultGateway(api_client)

    def probe(self) -> ApiProbeResult:
        return self.api_client.probe()

    def login(
        self,
        *,
        identifier: str,
        password: str,
        device_name: str,
        platform: str,
    ) -> LoginResult:
        result = self.api_client.login(
            LoginPayload(
                identifier=identifier,
                password=password,
                device_name=device_name,
                platform=platform,
            )
        )

        if result.error is not None:
            return result

        session = DesktopSession(
            identifier=identifier,
            user_id=result.user_id or "",
            device_id=result.device_id or "",
            session_id=result.session_id or "",
            access_token=result.access_token or "",
            refresh_token=result.refresh_token or "",
            token_type=result.token_type or "bearer",
        )
        self.session_store.set_session(session)
        return result

    def logout(self) -> None:
        self.session_store.clear()

    def set_session_vault_master_key(self, master_key_b64: str) -> None:
        session = self.session_store.current
        if session is None:
            raise ValueError("No active session.")

        parse_dev_aes256_key_b64(master_key_b64)
        self.session_store.set_vault_master_key(master_key_b64)

    def clear_session_vault_master_key(self) -> None:
        self.session_store.clear_vault_master_key()

    def current_session_vault_master_key(self) -> str | None:
        session = self.session_store.current
        if session is None:
            return None
        return session.vault_master_key_b64

    def has_session_vault_master_key(self) -> bool:
        return self.session_store.has_vault_master_key()

    def current_session(self) -> DesktopSession | None:
        return self.session_store.current

    def is_authenticated(self) -> bool:
        return self.session_store.is_authenticated()

    def refresh_session(self) -> RefreshResult:
        session = self.session_store.current
        if session is None:
            return RefreshResult(
                user_id=None,
                device_id=None,
                session_id=None,
                access_token=None,
                refresh_token=None,
                token_type=None,
                error="No active session.",
                status_code=401,
            )

        result = self.api_client.refresh(
            RefreshPayload(refresh_token=session.refresh_token)
        )

        if result.error is not None:
            self.session_store.clear()
            return result

        self.session_store.rotate_tokens(
            access_token=result.access_token or "",
            refresh_token=result.refresh_token or "",
            token_type=result.token_type or "bearer",
            session_id=result.session_id,
            user_id=result.user_id,
            device_id=result.device_id,
        )
        return result

    def fetch_credentials(self) -> ObjectListResult:
        return self._fetch_list_with_refresh(
            lambda session: self.vault_gateway.fetch_credentials(session)
        )

    def fetch_notes(self) -> ObjectListResult:
        return self._fetch_list_with_refresh(
            lambda session: self.vault_gateway.fetch_notes(session)
        )

    def fetch_files(self) -> ObjectListResult:
        return self._fetch_list_with_refresh(
            lambda session: self.vault_gateway.fetch_files(session)
        )

    def fetch_credential_detail(self, credential_id: str) -> ObjectDetailResult:
        return self._fetch_detail_with_refresh(
            lambda session: self.vault_gateway.fetch_credential_detail(session, credential_id)
        )

    def fetch_note_detail(self, note_id: str) -> ObjectDetailResult:
        return self._fetch_detail_with_refresh(
            lambda session: self.vault_gateway.fetch_note_detail(session, note_id)
        )

    def fetch_file_detail(self, file_id: str) -> ObjectDetailResult:
        return self._fetch_detail_with_refresh(
            lambda session: self.vault_gateway.fetch_file_detail(session, file_id)
        )

    def fetch_file_chunk(self, file_id: str, chunk_index: int) -> ObjectDetailResult:
        return self._fetch_detail_with_refresh(
            lambda session: self.vault_gateway.fetch_file_chunk(session, file_id, chunk_index)
        )

    def create_credential(
        self,
        *,
        device_name: str,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self._execute_create_with_refresh(
            lambda session: self.vault_gateway.create_credential(
                session,
                device_name=device_name,
                encrypted_metadata=encrypted_metadata,
                encrypted_payload=encrypted_payload,
                encryption_header=encryption_header,
            )
        )

    def prepare_credential(
        self,
        *,
        device_name: str,
    ) -> ObjectDetailResult:
        return self._fetch_detail_write_with_refresh(
            lambda session: self.vault_gateway.prepare_credential(
                session,
                device_name=device_name,
            )
        )

    def finalize_credential(
        self,
        *,
        device_name: str,
        credential_id: str,
        credential_version: int,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self._execute_create_with_refresh(
            lambda session: self.vault_gateway.finalize_credential(
                session,
                device_name=device_name,
                credential_id=credential_id,
                credential_version=credential_version,
                encrypted_metadata=encrypted_metadata,
                encrypted_payload=encrypted_payload,
                encryption_header=encryption_header,
            )
        )

    def update_credential(
        self,
        *,
        credential_id: str,
        device_name: str,
        expected_current_version: int,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self._execute_create_with_refresh(
            lambda session: self.vault_gateway.update_credential(
                session,
                credential_id=credential_id,
                device_name=device_name,
                expected_current_version=expected_current_version,
                encrypted_metadata=encrypted_metadata,
                encrypted_payload=encrypted_payload,
                encryption_header=encryption_header,
            )
        )

    def create_note(
        self,
        *,
        device_name: str,
        note_type: str,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self._execute_create_with_refresh(
            lambda session: self.vault_gateway.create_note(
                session,
                device_name=device_name,
                note_type=note_type,
                encrypted_metadata=encrypted_metadata,
                encrypted_payload=encrypted_payload,
                encryption_header=encryption_header,
            )
        )

    def prepare_note(
        self,
        *,
        device_name: str,
        note_type: str,
    ) -> ObjectDetailResult:
        return self._fetch_detail_write_with_refresh(
            lambda session: self.vault_gateway.prepare_note(
                session,
                device_name=device_name,
                note_type=note_type,
            )
        )

    def finalize_note(
        self,
        *,
        device_name: str,
        note_id: str,
        note_version: int,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self._execute_create_with_refresh(
            lambda session: self.vault_gateway.finalize_note(
                session,
                device_name=device_name,
                note_id=note_id,
                note_version=note_version,
                encrypted_metadata=encrypted_metadata,
                encrypted_payload=encrypted_payload,
                encryption_header=encryption_header,
            )
        )

    def update_note(
        self,
        *,
        note_id: str,
        device_name: str,
        expected_current_version: int,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self._execute_create_with_refresh(
            lambda session: self.vault_gateway.update_note(
                session,
                note_id=note_id,
                device_name=device_name,
                expected_current_version=expected_current_version,
                encrypted_metadata=encrypted_metadata,
                encrypted_payload=encrypted_payload,
                encryption_header=encryption_header,
            )
        )

    def create_file(
        self,
        *,
        device_name: str,
        encrypted_manifest: dict,
        encryption_header: dict,
        chunks: list[dict],
    ) -> ObjectCreateResult:
        return self._execute_create_with_refresh(
            lambda session: self.vault_gateway.create_file(
                session,
                device_name=device_name,
                encrypted_manifest=encrypted_manifest,
                encryption_header=encryption_header,
                chunks=chunks,
            )
        )

    def prepare_file(
        self,
        *,
        device_name: str,
        chunk_count: int,
    ) -> ObjectDetailResult:
        return self._fetch_detail_write_with_refresh(
            lambda session: self.vault_gateway.prepare_file(
                session,
                device_name=device_name,
                chunk_count=chunk_count,
            )
        )

    def finalize_file(
        self,
        *,
        device_name: str,
        file_id: str,
        file_version: int,
        encrypted_manifest: dict,
        encryption_header: dict,
        chunks: list[dict],
    ) -> ObjectCreateResult:
        return self._execute_create_with_refresh(
            lambda session: self.vault_gateway.finalize_file(
                session,
                device_name=device_name,
                file_id=file_id,
                file_version=file_version,
                encrypted_manifest=encrypted_manifest,
                encryption_header=encryption_header,
                chunks=chunks,
            )
        )

    def _fetch_list_with_refresh(
        self,
        fetcher: Callable[[DesktopSession], ObjectListResult],
    ) -> ObjectListResult:
        session = self.session_store.current
        if session is None:
            return ObjectListResult(
                items=[],
                error="No active session.",
                status_code=401,
            )

        result = fetcher(session)
        if result.status_code != 401:
            return result

        refresh_result = self.refresh_session()
        if refresh_result.error is not None:
            return ObjectListResult(
                items=[],
                error=f"Session refresh failed. Error: {refresh_result.error}",
                status_code=401,
            )

        refreshed_session = self.session_store.current
        if refreshed_session is None:
            return ObjectListResult(
                items=[],
                error="Session refresh failed.",
                status_code=401,
            )

        return fetcher(refreshed_session)

    def _fetch_detail_with_refresh(
        self,
        fetcher: Callable[[DesktopSession], ObjectDetailResult],
    ) -> ObjectDetailResult:
        session = self.session_store.current
        if session is None:
            return ObjectDetailResult(
                item=None,
                error="No active session.",
                status_code=401,
            )

        result = fetcher(session)
        if result.status_code != 401:
            return result

        refresh_result = self.refresh_session()
        if refresh_result.error is not None:
            return ObjectDetailResult(
                item=None,
                error=f"Session refresh failed. Error: {refresh_result.error}",
                status_code=401,
            )

        refreshed_session = self.session_store.current
        if refreshed_session is None:
            return ObjectDetailResult(
                item=None,
                error="Session refresh failed.",
                status_code=401,
            )

        return fetcher(refreshed_session)

    def _fetch_detail_write_with_refresh(
        self,
        fetcher: Callable[[DesktopSession], ObjectDetailResult],
    ) -> ObjectDetailResult:
        session = self.session_store.current
        if session is None:
            return ObjectDetailResult(
                item=None,
                error="No active session.",
                status_code=401,
            )

        result = fetcher(session)
        if result.status_code != 401:
            return result

        refresh_result = self.refresh_session()
        if refresh_result.error is not None:
            return ObjectDetailResult(
                item=None,
                error=f"Session refresh failed. Error: {refresh_result.error}",
                status_code=401,
            )

        refreshed_session = self.session_store.current
        if refreshed_session is None:
            return ObjectDetailResult(
                item=None,
                error="Session refresh failed.",
                status_code=401,
            )

        return fetcher(refreshed_session)

    def _execute_create_with_refresh(
        self,
        creator: Callable[[DesktopSession], ObjectCreateResult],
    ) -> ObjectCreateResult:
        session = self.session_store.current
        if session is None:
            return ObjectCreateResult(
                item=None,
                error="No active session.",
                status_code=401,
            )

        result = creator(session)
        if result.status_code != 401:
            return result

        refresh_result = self.refresh_session()
        if refresh_result.error is not None:
            return ObjectCreateResult(
                item=None,
                error=f"Session refresh failed. Error: {refresh_result.error}",
                status_code=401,
            )

        refreshed_session = self.session_store.current
        if refreshed_session is None:
            return ObjectCreateResult(
                item=None,
                error="Session refresh failed.",
                status_code=401,
            )

        return creator(refreshed_session)
