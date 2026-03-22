from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class LoginPayload:
    identifier: str
    password: str
    device_name: str
    platform: str


@dataclass(frozen=True)
class RefreshPayload:
    refresh_token: str


@dataclass(frozen=True)
class ApiProbeResult:
    health_ok: bool
    project_name: str | None
    version: str | None
    environment: str | None
    error: str | None = None
    status_code: int | None = None


@dataclass(frozen=True)
class LoginResult:
    user_id: str | None
    device_id: str | None
    session_id: str | None
    access_token: str | None
    refresh_token: str | None
    token_type: str | None
    error: str | None = None
    status_code: int | None = None


@dataclass(frozen=True)
class RefreshResult:
    user_id: str | None
    device_id: str | None
    session_id: str | None
    access_token: str | None
    refresh_token: str | None
    token_type: str | None
    error: str | None = None
    status_code: int | None = None


@dataclass(frozen=True)
class ObjectListResult:
    items: list[dict[str, Any]]
    error: str | None = None
    status_code: int | None = None


@dataclass(frozen=True)
class ObjectDetailResult:
    item: dict[str, Any] | None
    error: str | None = None
    status_code: int | None = None


@dataclass(frozen=True)
class ObjectCreateResult:
    item: dict[str, Any] | None
    error: str | None = None
    status_code: int | None = None


class VaultApiClient:
    def __init__(self, base_url: str, timeout_seconds: float = 8.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def _headers(self, access_token: str | None = None) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        return headers

    def _error_text(self, response: httpx.Response) -> str:
        try:
            data = response.json()
        except ValueError:
            return response.text or f"HTTP {response.status_code}"

        detail = data.get("detail")
        if isinstance(detail, str) and detail.strip():
            return detail
        return response.text or f"HTTP {response.status_code}"

    def probe(self) -> ApiProbeResult:
        try:
            health_response = httpx.get(
                f"{self.base_url}/health",
                timeout=self.timeout_seconds,
            )
            health_response.raise_for_status()

            system_response = httpx.get(
                f"{self.base_url}/api/v1/system",
                timeout=self.timeout_seconds,
            )
            system_response.raise_for_status()

            system_data = system_response.json()

            return ApiProbeResult(
                health_ok=health_response.json().get("status") == "ok",
                project_name=system_data.get("project_name"),
                version=system_data.get("version"),
                environment=system_data.get("environment"),
                error=None,
                status_code=system_response.status_code,
            )
        except httpx.HTTPStatusError as exc:
            return ApiProbeResult(
                health_ok=False,
                project_name=None,
                version=None,
                environment=None,
                error=self._error_text(exc.response),
                status_code=exc.response.status_code,
            )
        except httpx.RequestError as exc:
            return ApiProbeResult(
                health_ok=False,
                project_name=None,
                version=None,
                environment=None,
                error=str(exc),
                status_code=None,
            )

    def login(self, payload: LoginPayload) -> LoginResult:
        try:
            response = httpx.post(
                f"{self.base_url}/api/v1/auth/login",
                json={
                    "identifier": payload.identifier,
                    "password": payload.password,
                    "device_name": payload.device_name,
                    "platform": payload.platform,
                },
                headers=self._headers(),
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()
            session = data.get("session", {})
            tokens = data.get("tokens", {})

            return LoginResult(
                user_id=data.get("user_id"),
                device_id=data.get("device_id"),
                session_id=session.get("session_id"),
                access_token=tokens.get("access_token"),
                refresh_token=tokens.get("refresh_token"),
                token_type=tokens.get("token_type"),
                error=None,
                status_code=response.status_code,
            )
        except httpx.HTTPStatusError as exc:
            return LoginResult(
                user_id=None,
                device_id=None,
                session_id=None,
                access_token=None,
                refresh_token=None,
                token_type=None,
                error=self._error_text(exc.response),
                status_code=exc.response.status_code,
            )
        except httpx.RequestError as exc:
            return LoginResult(
                user_id=None,
                device_id=None,
                session_id=None,
                access_token=None,
                refresh_token=None,
                token_type=None,
                error=str(exc),
                status_code=None,
            )

    def refresh(self, payload: RefreshPayload) -> RefreshResult:
        try:
            response = httpx.post(
                f"{self.base_url}/api/v1/auth/refresh",
                json={"refresh_token": payload.refresh_token},
                headers=self._headers(),
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()
            session = data.get("session", {})
            tokens = data.get("tokens", {})

            return RefreshResult(
                user_id=session.get("user_id"),
                device_id=session.get("device_id"),
                session_id=session.get("session_id"),
                access_token=tokens.get("access_token"),
                refresh_token=tokens.get("refresh_token"),
                token_type=tokens.get("token_type"),
                error=None,
                status_code=response.status_code,
            )
        except httpx.HTTPStatusError as exc:
            return RefreshResult(
                user_id=None,
                device_id=None,
                session_id=None,
                access_token=None,
                refresh_token=None,
                token_type=None,
                error=self._error_text(exc.response),
                status_code=exc.response.status_code,
            )
        except httpx.RequestError as exc:
            return RefreshResult(
                user_id=None,
                device_id=None,
                session_id=None,
                access_token=None,
                refresh_token=None,
                token_type=None,
                error=str(exc),
                status_code=None,
            )

    def fetch_credentials(self, access_token: str | None = None) -> ObjectListResult:
        return self._fetch_list("/api/v1/vault/credentials", access_token=access_token)

    def fetch_notes(self, access_token: str | None = None) -> ObjectListResult:
        return self._fetch_list("/api/v1/vault/notes", access_token=access_token)

    def fetch_files(self, access_token: str | None = None) -> ObjectListResult:
        return self._fetch_list("/api/v1/vault/files", access_token=access_token)

    def fetch_credential_detail(
        self,
        credential_id: str,
        access_token: str | None = None,
    ) -> ObjectDetailResult:
        return self._fetch_detail(
            f"/api/v1/vault/credentials/{credential_id}",
            access_token=access_token,
        )

    def fetch_note_detail(
        self,
        note_id: str,
        access_token: str | None = None,
    ) -> ObjectDetailResult:
        return self._fetch_detail(
            f"/api/v1/vault/notes/{note_id}",
            access_token=access_token,
        )

    def fetch_file_detail(
        self,
        file_id: str,
        access_token: str | None = None,
    ) -> ObjectDetailResult:
        return self._fetch_detail(
            f"/api/v1/vault/files/{file_id}",
            access_token=access_token,
        )

    def create_credential(
        self,
        *,
        device_name: str,
        encrypted_metadata: dict[str, Any] | None,
        encrypted_payload: dict[str, Any],
        encryption_header: dict[str, Any],
        access_token: str | None = None,
    ) -> ObjectCreateResult:
        return self._post_object(
            "/api/v1/vault/credentials",
            payload={
                "device_name": device_name,
                "encrypted_metadata": encrypted_metadata,
                "encrypted_payload": encrypted_payload,
                "encryption_header": encryption_header,
            },
            access_token=access_token,
        )

    def _fetch_list(self, path: str, *, access_token: str | None) -> ObjectListResult:
        try:
            response = httpx.get(
                f"{self.base_url}{path}",
                headers=self._headers(access_token),
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()

            return ObjectListResult(
                items=data.get("items", []),
                error=None,
                status_code=response.status_code,
            )
        except httpx.HTTPStatusError as exc:
            return ObjectListResult(
                items=[],
                error=self._error_text(exc.response),
                status_code=exc.response.status_code,
            )
        except httpx.RequestError as exc:
            return ObjectListResult(
                items=[],
                error=str(exc),
                status_code=None,
            )

    def _fetch_detail(self, path: str, *, access_token: str | None) -> ObjectDetailResult:
        try:
            response = httpx.get(
                f"{self.base_url}{path}",
                headers=self._headers(access_token),
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()

            return ObjectDetailResult(
                item=data,
                error=None,
                status_code=response.status_code,
            )
        except httpx.HTTPStatusError as exc:
            return ObjectDetailResult(
                item=None,
                error=self._error_text(exc.response),
                status_code=exc.response.status_code,
            )
        except httpx.RequestError as exc:
            return ObjectDetailResult(
                item=None,
                error=str(exc),
                status_code=None,
            )

    def _post_object(
        self,
        path: str,
        *,
        payload: dict[str, Any],
        access_token: str | None,
    ) -> ObjectCreateResult:
        try:
            response = httpx.post(
                f"{self.base_url}{path}",
                json=payload,
                headers=self._headers(access_token),
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()

            return ObjectCreateResult(
                item=data,
                error=None,
                status_code=response.status_code,
            )
        except httpx.HTTPStatusError as exc:
            return ObjectCreateResult(
                item=None,
                error=self._error_text(exc.response),
                status_code=exc.response.status_code,
            )
        except httpx.RequestError as exc:
            return ObjectCreateResult(
                item=None,
                error=str(exc),
                status_code=None,
            )
