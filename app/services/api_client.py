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
