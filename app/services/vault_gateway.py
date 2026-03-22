from __future__ import annotations

from typing import Protocol

from app.core.session import DesktopSession
from app.services.api_client import ObjectDetailResult, ObjectListResult, VaultApiClient


class VaultGateway(Protocol):
    def fetch_credentials(self, session: DesktopSession) -> ObjectListResult: ...
    def fetch_notes(self, session: DesktopSession) -> ObjectListResult: ...
    def fetch_files(self, session: DesktopSession) -> ObjectListResult: ...

    def fetch_credential_detail(
        self,
        session: DesktopSession,
        credential_id: str,
    ) -> ObjectDetailResult: ...

    def fetch_note_detail(
        self,
        session: DesktopSession,
        note_id: str,
    ) -> ObjectDetailResult: ...

    def fetch_file_detail(
        self,
        session: DesktopSession,
        file_id: str,
    ) -> ObjectDetailResult: ...


class DevVaultGateway:
    def __init__(self, api_client: VaultApiClient) -> None:
        self.api_client = api_client

    def fetch_credentials(self, session: DesktopSession) -> ObjectListResult:
        return self.api_client.fetch_credentials(
            identifier=session.identifier,
            access_token=session.access_token,
        )

    def fetch_notes(self, session: DesktopSession) -> ObjectListResult:
        return self.api_client.fetch_notes(
            identifier=session.identifier,
            access_token=session.access_token,
        )

    def fetch_files(self, session: DesktopSession) -> ObjectListResult:
        return self.api_client.fetch_files(
            identifier=session.identifier,
            access_token=session.access_token,
        )

    def fetch_credential_detail(
        self,
        session: DesktopSession,
        credential_id: str,
    ) -> ObjectDetailResult:
        return self.api_client.fetch_credential_detail(
            identifier=session.identifier,
            credential_id=credential_id,
            access_token=session.access_token,
        )

    def fetch_note_detail(
        self,
        session: DesktopSession,
        note_id: str,
    ) -> ObjectDetailResult:
        return self.api_client.fetch_note_detail(
            identifier=session.identifier,
            note_id=note_id,
            access_token=session.access_token,
        )

    def fetch_file_detail(
        self,
        session: DesktopSession,
        file_id: str,
    ) -> ObjectDetailResult:
        return self.api_client.fetch_file_detail(
            identifier=session.identifier,
            file_id=file_id,
            access_token=session.access_token,
        )


class AuthenticatedVaultGateway:
    def __init__(self, api_client: VaultApiClient) -> None:
        self.api_client = api_client

    def fetch_credentials(self, session: DesktopSession) -> ObjectListResult:
        return self.api_client.fetch_vault_credentials(
            access_token=session.access_token,
        )

    def fetch_notes(self, session: DesktopSession) -> ObjectListResult:
        return self.api_client.fetch_vault_notes(
            access_token=session.access_token,
        )

    def fetch_files(self, session: DesktopSession) -> ObjectListResult:
        return self.api_client.fetch_vault_files(
            access_token=session.access_token,
        )

    def fetch_credential_detail(
        self,
        session: DesktopSession,
        credential_id: str,
    ) -> ObjectDetailResult:
        return self.api_client.fetch_vault_credential_detail(
            credential_id=credential_id,
            access_token=session.access_token,
        )

    def fetch_note_detail(
        self,
        session: DesktopSession,
        note_id: str,
    ) -> ObjectDetailResult:
        return self.api_client.fetch_vault_note_detail(
            note_id=note_id,
            access_token=session.access_token,
        )

    def fetch_file_detail(
        self,
        session: DesktopSession,
        file_id: str,
    ) -> ObjectDetailResult:
        return self.api_client.fetch_vault_file_detail(
            file_id=file_id,
            access_token=session.access_token,
        )
