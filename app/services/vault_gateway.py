from __future__ import annotations

from typing import Protocol

from app.core.session import DesktopSession
from app.services.api_client import (
    ObjectCreateResult,
    ObjectDetailResult,
    ObjectListResult,
    VaultApiClient,
)


class VaultGateway(Protocol):
    def fetch_credentials(self, session: DesktopSession) -> ObjectListResult: ...
    def fetch_notes(self, session: DesktopSession) -> ObjectListResult: ...
    def fetch_files(self, session: DesktopSession) -> ObjectListResult: ...
    def fetch_credential_detail(self, session: DesktopSession, credential_id: str) -> ObjectDetailResult: ...
    def fetch_note_detail(self, session: DesktopSession, note_id: str) -> ObjectDetailResult: ...
    def fetch_file_detail(self, session: DesktopSession, file_id: str) -> ObjectDetailResult: ...
    def fetch_file_chunk(self, session: DesktopSession, file_id: str, chunk_index: int) -> ObjectDetailResult: ...

    def create_credential(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        plaintext_app_name: str | None = None,
        plaintext_username: str | None = None,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult: ...

    def prepare_credential(
        self,
        session: DesktopSession,
        *,
        device_name: str,
    ) -> ObjectDetailResult: ...

    def finalize_credential(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        credential_id: str,
        credential_version: int,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult: ...

    def update_credential(
        self,
        session: DesktopSession,
        *,
        credential_id: str,
        device_name: str,
        expected_current_version: int,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult: ...

    def delete_credential(
        self,
        session: DesktopSession,
        *,
        credential_id: str,
    ) -> ObjectCreateResult: ...

    def create_note(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        note_type: str,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult: ...

    def prepare_note(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        note_type: str,
    ) -> ObjectDetailResult: ...

    def finalize_note(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        note_id: str,
        note_version: int,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult: ...

    def update_note(
        self,
        session: DesktopSession,
        *,
        note_id: str,
        device_name: str,
        expected_current_version: int,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult: ...

    def delete_note(
        self,
        session: DesktopSession,
        *,
        note_id: str,
    ) -> ObjectCreateResult: ...

    def create_file(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        plaintext_filename: str,
        plaintext_size_bytes: int,
        encrypted_manifest: dict,
        encryption_header: dict,
        chunks: list[dict],
    ) -> ObjectCreateResult: ...

    def prepare_file(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        chunk_count: int,
    ) -> ObjectDetailResult: ...

    def finalize_file(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        file_id: str,
        file_version: int,
        encrypted_manifest: dict,
        encryption_header: dict,
        chunks: list[dict],
    ) -> ObjectCreateResult: ...


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

    def fetch_file_chunk(
        self,
        session: DesktopSession,
        file_id: str,
        chunk_index: int,
    ) -> ObjectDetailResult:
        return self.api_client.fetch_file_chunk(
            file_id,
            chunk_index,
            access_token=session.access_token,
        )

    def create_credential(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        plaintext_app_name: str | None = None,
        plaintext_username: str | None = None,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self.api_client.create_credential(
            device_name=device_name,
            plaintext_app_name=plaintext_app_name,
            plaintext_username=plaintext_username,
            encrypted_metadata=encrypted_metadata,
            encrypted_payload=encrypted_payload,
            encryption_header=encryption_header,
            access_token=session.access_token,
        )

    def prepare_credential(
        self,
        session: DesktopSession,
        *,
        device_name: str,
    ) -> ObjectDetailResult:
        return self.api_client.prepare_credential(
            device_name=device_name,
            access_token=session.access_token,
        )

    def finalize_credential(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        credential_id: str,
        credential_version: int,
        plaintext_app_name: str | None = None,
        plaintext_username: str | None = None,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self.api_client.finalize_credential(
            device_name=device_name,
            credential_id=credential_id,
            credential_version=credential_version,
            plaintext_app_name=plaintext_app_name,
            plaintext_username=plaintext_username,
            encrypted_metadata=encrypted_metadata,
            encrypted_payload=encrypted_payload,
            encryption_header=encryption_header,
            access_token=session.access_token,
        )

    def update_credential(
        self,
        session: DesktopSession,
        *,
        credential_id: str,
        device_name: str,
        expected_current_version: int,
        plaintext_app_name: str | None = None,
        plaintext_username: str | None = None,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self.api_client.update_credential(
            credential_id=credential_id,
            device_name=device_name,
            expected_current_version=expected_current_version,
            plaintext_app_name=plaintext_app_name,
            plaintext_username=plaintext_username,
            encrypted_metadata=encrypted_metadata,
            encrypted_payload=encrypted_payload,
            encryption_header=encryption_header,
            access_token=session.access_token,
        )

    def delete_credential(
        self,
        session: DesktopSession,
        *,
        credential_id: str,
    ) -> ObjectCreateResult:
        return self.api_client.delete_credential(
            credential_id=credential_id,
            access_token=session.access_token,
        )

    def create_note(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        note_type: str,
        plaintext_title: str | None = None,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self.api_client.create_note(
            device_name=device_name,
            note_type=note_type,
            plaintext_title=plaintext_title,
            encrypted_metadata=encrypted_metadata,
            encrypted_payload=encrypted_payload,
            encryption_header=encryption_header,
            access_token=session.access_token,
        )

    def prepare_note(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        note_type: str,
    ) -> ObjectDetailResult:
        return self.api_client.prepare_note(
            device_name=device_name,
            note_type=note_type,
            access_token=session.access_token,
        )

    def finalize_note(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        note_id: str,
        note_version: int,
        plaintext_title: str | None = None,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self.api_client.finalize_note(
            device_name=device_name,
            note_id=note_id,
            note_version=note_version,
            plaintext_title=plaintext_title,
            encrypted_metadata=encrypted_metadata,
            encrypted_payload=encrypted_payload,
            encryption_header=encryption_header,
            access_token=session.access_token,
        )

    def update_note(
        self,
        session: DesktopSession,
        *,
        note_id: str,
        device_name: str,
        expected_current_version: int,
        plaintext_title: str | None = None,
        encrypted_metadata: dict | None,
        encrypted_payload: dict,
        encryption_header: dict,
    ) -> ObjectCreateResult:
        return self.api_client.update_note(
            note_id=note_id,
            device_name=device_name,
            expected_current_version=expected_current_version,
            plaintext_title=plaintext_title,
            encrypted_metadata=encrypted_metadata,
            encrypted_payload=encrypted_payload,
            encryption_header=encryption_header,
            access_token=session.access_token,
        )

    def delete_note(
        self,
        session: DesktopSession,
        *,
        note_id: str,
    ) -> ObjectCreateResult:
        return self.api_client.delete_note(
            note_id=note_id,
            access_token=session.access_token,
        )

    def create_file(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        encrypted_manifest: dict,
        encryption_header: dict,
        chunks: list[dict],
    ) -> ObjectCreateResult:
        return self.api_client.create_file(
            device_name=device_name,
            plaintext_filename=plaintext_filename,
            plaintext_size_bytes=plaintext_size_bytes,
            encrypted_manifest=encrypted_manifest,
            encryption_header=encryption_header,
            chunks=chunks,
            access_token=session.access_token,
        )

    def prepare_file(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        chunk_count: int,
    ) -> ObjectDetailResult:
        return self.api_client.prepare_file(
            device_name=device_name,
            chunk_count=chunk_count,
            access_token=session.access_token,
        )

    def finalize_file(
        self,
        session: DesktopSession,
        *,
        device_name: str,
        file_id: str,
        file_version: int,
        plaintext_filename: str,
        plaintext_size_bytes: int,
        encrypted_manifest: dict,
        encryption_header: dict,
        chunks: list[dict],
    ) -> ObjectCreateResult:
        return self.api_client.finalize_file(
            device_name=device_name,
            file_id=file_id,
            file_version=file_version,
            plaintext_filename=plaintext_filename,
            plaintext_size_bytes=plaintext_size_bytes,
            encrypted_manifest=encrypted_manifest,
            encryption_header=encryption_header,
            chunks=chunks,
            access_token=session.access_token,
        )


DevVaultGateway = AuthenticatedVaultGateway
