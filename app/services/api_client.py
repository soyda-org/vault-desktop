from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class ApiProbeResult:
    health_ok: bool
    project_name: str | None
    version: str | None
    environment: str | None
    error: str | None = None


@dataclass(frozen=True)
class LoginPayload:
    identifier: str
    password: str
    device_name: str
    platform: str


@dataclass(frozen=True)
class LoginResult:
    user_id: str | None
    device_id: str | None
    session_id: str | None
    access_token: str | None
    refresh_token: str | None
    token_type: str | None
    error: str | None = None


@dataclass(frozen=True)
class ObjectListResult:
    items: list[dict]
    error: str | None = None


class VaultApiClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def probe(self) -> ApiProbeResult:
        try:
            with httpx.Client(base_url=self.base_url, timeout=5.0) as client:
                health_response = client.get("/health")
                system_response = client.get("/api/v1/system")

            health_response.raise_for_status()
            system_response.raise_for_status()

            health_json = health_response.json()
            system_json = system_response.json()

            return ApiProbeResult(
                health_ok=health_json.get("status") == "ok",
                project_name=system_json.get("project_name"),
                version=system_json.get("version"),
                environment=system_json.get("environment"),
                error=None,
            )
        except Exception as exc:
            return ApiProbeResult(
                health_ok=False,
                project_name=None,
                version=None,
                environment=None,
                error=str(exc),
            )

    def login(self, payload: LoginPayload) -> LoginResult:
        try:
            with httpx.Client(base_url=self.base_url, timeout=10.0) as client:
                response = client.post(
                    "/api/v1/auth/login",
                    json={
                        "identifier": payload.identifier,
                        "password": payload.password,
                        "device_name": payload.device_name,
                        "platform": payload.platform,
                    },
                )

            response.raise_for_status()
            data = response.json()

            return LoginResult(
                user_id=data.get("user_id"),
                device_id=data.get("device_id"),
                session_id=(data.get("session") or {}).get("session_id"),
                access_token=(data.get("tokens") or {}).get("access_token"),
                refresh_token=(data.get("tokens") or {}).get("refresh_token"),
                token_type=(data.get("tokens") or {}).get("token_type"),
                error=None,
            )
        except Exception as exc:
            return LoginResult(
                user_id=None,
                device_id=None,
                session_id=None,
                access_token=None,
                refresh_token=None,
                token_type=None,
                error=str(exc),
            )

    def fetch_credentials(self, identifier: str, access_token: str | None = None) -> ObjectListResult:
        return self._fetch_object_list(
            f"/api/v1/dev/credentials/user/{identifier}",
            access_token=access_token,
        )

    def fetch_notes(self, identifier: str, access_token: str | None = None) -> ObjectListResult:
        return self._fetch_object_list(
            f"/api/v1/dev/notes/user/{identifier}",
            access_token=access_token,
        )

    def fetch_files(self, identifier: str, access_token: str | None = None) -> ObjectListResult:
        return self._fetch_object_list(
            f"/api/v1/dev/files/user/{identifier}",
            access_token=access_token,
        )

    def _fetch_object_list(self, path: str, access_token: str | None = None) -> ObjectListResult:
        try:
            headers = {}
            if access_token:
                headers["Authorization"] = f"Bearer {access_token}"

            with httpx.Client(base_url=self.base_url, timeout=10.0) as client:
                response = client.get(path, headers=headers)

            response.raise_for_status()
            data = response.json()

            return ObjectListResult(
                items=data.get("items", []),
                error=None,
            )
        except Exception as exc:
            return ObjectListResult(
                items=[],
                error=str(exc),
            )
