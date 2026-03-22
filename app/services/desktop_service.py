from __future__ import annotations

from app.core.session import DesktopSession, SessionStore
from app.services.api_client import (
    ApiProbeResult,
    LoginPayload,
    LoginResult,
    ObjectDetailResult,
    ObjectListResult,
    VaultApiClient,
)
from app.services.vault_gateway import DevVaultGateway, VaultGateway


class VaultDesktopService:
    def __init__(
        self,
        api_client: VaultApiClient,
        vault_gateway: VaultGateway | None = None,
        session_store: SessionStore | None = None,
    ) -> None:
        self.api_client = api_client
        self.session_store = session_store or SessionStore()
        self.vault_gateway = vault_gateway or DevVaultGateway(api_client)

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
            token_type=result.token_type or "",
        )
        self.session_store.set_session(session)
        return result

    def logout(self) -> None:
        self.session_store.clear()

    def current_session(self) -> DesktopSession | None:
        return self.session_store.current

    def is_authenticated(self) -> bool:
        return self.session_store.is_authenticated()

    def fetch_credentials(self) -> ObjectListResult:
        session = self.session_store.current
        if session is None:
            return ObjectListResult(items=[], error="No active session.")

        return self.vault_gateway.fetch_credentials(session)

    def fetch_notes(self) -> ObjectListResult:
        session = self.session_store.current
        if session is None:
            return ObjectListResult(items=[], error="No active session.")

        return self.vault_gateway.fetch_notes(session)

    def fetch_files(self) -> ObjectListResult:
        session = self.session_store.current
        if session is None:
            return ObjectListResult(items=[], error="No active session.")

        return self.vault_gateway.fetch_files(session)

    def fetch_credential_detail(self, credential_id: str) -> ObjectDetailResult:
        session = self.session_store.current
        if session is None:
            return ObjectDetailResult(item=None, error="No active session.")

        return self.vault_gateway.fetch_credential_detail(session, credential_id)

    def fetch_note_detail(self, note_id: str) -> ObjectDetailResult:
        session = self.session_store.current
        if session is None:
            return ObjectDetailResult(item=None, error="No active session.")

        return self.vault_gateway.fetch_note_detail(session, note_id)

    def fetch_file_detail(self, file_id: str) -> ObjectDetailResult:
        session = self.session_store.current
        if session is None:
            return ObjectDetailResult(item=None, error="No active session.")

        return self.vault_gateway.fetch_file_detail(session, file_id)
