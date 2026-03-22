from __future__ import annotations

from typing import Protocol

from app.core.session import DesktopSession
from app.services.api_client import ObjectDetailResult, ObjectListResult, VaultApiClient


class VaultGateway(Protocol):
    def fetch_credentials(self, session: DesktopSession) -> ObjectListResult: ...
    def fetch_notes(self, session: DesktopSession) -> ObjectListResult: ...
    def fetch_files(self, session: DesktopSession) -> ObjectListResult: ...
    def fetch_credential_detail(self, session: DesktopSession, credential_id: str) -> ObjectDetailResult: ...
    def fetch_note_detail(self, session: DesktopSession, note_id: str) -> ObjectDetailResult: ...
    def fetch_file_detail(self, session: DesktopSession, file_id: str) -> ObjectDetailResult: ...


class AuthenticatedVaultGateway:
    def __init__(self, api_client: VaultApiClient) -> None:
        self.api_client = api_client

    def fetch_credentials(self, session: DesktopSession) -> ObjectListResult:
        return self.api_client.fetch_credentials(access_token=session.access_token)

    def fetch_notes(self, session: DesktopSession) -> ObjectListResult:
        return self.api_client.fetch_notes(access_token=session.access_token)

    def fetch_files(self, session: DesktopSession) -> ObjectListResult:
        return self.api_client.fetch_files(access_token=session.access_token)

    def fetch_credential_detail(
        self,
        session: DesktopSession,
        credential_id: str,
    ) -> ObjectDetailResult:
        return self.api_client.fetch_credential_detail(
            credential_id,
            access_token=session.access_token,
        )

    def fetch_note_detail(
        self,
        session: DesktopSession,
        note_id: str,
    ) -> ObjectDetailResult:
        return self.api_client.fetch_note_detail(
            note_id,
            access_token=session.access_token,
        )

    def fetch_file_detail(
        self,
        session: DesktopSession,
        file_id: str,
    ) -> ObjectDetailResult:
        return self.api_client.fetch_file_detail(
            file_id,
            access_token=session.access_token,
        )


DevVaultGateway = AuthenticatedVaultGateway
