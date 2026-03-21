from app.services.api_client import ApiProbeResult, VaultApiClient


class DummyResponse:
    def __init__(self, json_payload: dict, status_code: int = 200) -> None:
        self._json_payload = json_payload
        self.status_code = status_code

    def json(self) -> dict:
        return self._json_payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class DummyClient:
    def __init__(self, responses: dict[str, DummyResponse]) -> None:
        self.responses = responses

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, path: str):
        return self.responses[path]


def test_probe_success(monkeypatch) -> None:
    responses = {
        "/health": DummyResponse({"status": "ok"}),
        "/api/v1/system": DummyResponse(
            {
                "project_name": "vault-api",
                "version": "0.1.0",
                "environment": "dev",
            }
        ),
    }

    def fake_client(*args, **kwargs):
        return DummyClient(responses)

    monkeypatch.setattr("app.services.api_client.httpx.Client", fake_client)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.probe()

    assert isinstance(result, ApiProbeResult)
    assert result.health_ok is True
    assert result.project_name == "vault-api"
    assert result.version == "0.1.0"
    assert result.environment == "dev"
    assert result.error is None


def test_probe_failure(monkeypatch) -> None:
    def fake_client(*args, **kwargs):
        raise RuntimeError("connection failed")

    monkeypatch.setattr("app.services.api_client.httpx.Client", fake_client)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.probe()

    assert result.health_ok is False
    assert result.error is not None
