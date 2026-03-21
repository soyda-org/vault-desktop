from app.services.api_client import (
    ApiProbeResult,
    LoginPayload,
    LoginResult,
    ObjectDetailResult,
    ObjectListResult,
    VaultApiClient,
)


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

    def get(self, path: str, headers: dict | None = None):
        return self.responses[path]

    def post(self, path: str, json: dict):
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


def test_login_success(monkeypatch) -> None:
    responses = {
        "/api/v1/auth/login": DummyResponse(
            {
                "user_id": "user_001",
                "device_id": "device_001",
                "session": {
                    "session_id": "session_001",
                },
                "tokens": {
                    "access_token": "access-token",
                    "refresh_token": "refresh-token",
                    "token_type": "bearer",
                },
            }
        )
    }

    def fake_client(*args, **kwargs):
        return DummyClient(responses)

    monkeypatch.setattr("app.services.api_client.httpx.Client", fake_client)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.login(
        LoginPayload(
            identifier="alice",
            password="strong-password",
            device_name="desktop-dev",
            platform="linux",
        )
    )

    assert isinstance(result, LoginResult)
    assert result.user_id == "user_001"
    assert result.device_id == "device_001"
    assert result.session_id == "session_001"
    assert result.access_token == "access-token"
    assert result.error is None


def test_login_failure(monkeypatch) -> None:
    def fake_client(*args, **kwargs):
        raise RuntimeError("login failed")

    monkeypatch.setattr("app.services.api_client.httpx.Client", fake_client)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.login(
        LoginPayload(
            identifier="alice",
            password="wrong-password",
            device_name="desktop-dev",
            platform="linux",
        )
    )

    assert result.user_id is None
    assert result.error is not None


def test_fetch_credentials_success(monkeypatch) -> None:
    responses = {
        "/api/v1/dev/credentials/user/alice": DummyResponse(
            {
                "items": [
                    {
                        "credential_id": "cred_001",
                        "state": "active",
                    }
                ]
            }
        )
    }

    def fake_client(*args, **kwargs):
        return DummyClient(responses)

    monkeypatch.setattr("app.services.api_client.httpx.Client", fake_client)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.fetch_credentials("alice", access_token="access-token")

    assert isinstance(result, ObjectListResult)
    assert len(result.items) == 1
    assert result.items[0]["credential_id"] == "cred_001"
    assert result.error is None


def test_fetch_notes_success(monkeypatch) -> None:
    responses = {
        "/api/v1/dev/notes/user/alice": DummyResponse(
            {
                "items": [
                    {
                        "note_id": "note_001",
                        "note_type": "note",
                    }
                ]
            }
        )
    }

    def fake_client(*args, **kwargs):
        return DummyClient(responses)

    monkeypatch.setattr("app.services.api_client.httpx.Client", fake_client)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.fetch_notes("alice", access_token="access-token")

    assert isinstance(result, ObjectListResult)
    assert len(result.items) == 1
    assert result.items[0]["note_id"] == "note_001"
    assert result.error is None


def test_fetch_files_success(monkeypatch) -> None:
    responses = {
        "/api/v1/dev/files/user/alice": DummyResponse(
            {
                "items": [
                    {
                        "file_id": "file_001",
                        "state": "active",
                    }
                ]
            }
        )
    }

    def fake_client(*args, **kwargs):
        return DummyClient(responses)

    monkeypatch.setattr("app.services.api_client.httpx.Client", fake_client)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.fetch_files("alice", access_token="access-token")

    assert isinstance(result, ObjectListResult)
    assert len(result.items) == 1
    assert result.items[0]["file_id"] == "file_001"
    assert result.error is None


def test_fetch_credential_detail_success(monkeypatch) -> None:
    responses = {
        "/api/v1/dev/credentials/user/alice/cred_001": DummyResponse(
            {
                "credential_id": "cred_001",
                "state": "active",
                "current_version": 1,
            }
        )
    }

    def fake_client(*args, **kwargs):
        return DummyClient(responses)

    monkeypatch.setattr("app.services.api_client.httpx.Client", fake_client)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.fetch_credential_detail("alice", "cred_001", access_token="access-token")

    assert isinstance(result, ObjectDetailResult)
    assert result.item is not None
    assert result.item["credential_id"] == "cred_001"
    assert result.error is None


def test_fetch_note_detail_success(monkeypatch) -> None:
    responses = {
        "/api/v1/dev/notes/user/alice/note_001": DummyResponse(
            {
                "note_id": "note_001",
                "note_type": "note",
                "state": "active",
            }
        )
    }

    def fake_client(*args, **kwargs):
        return DummyClient(responses)

    monkeypatch.setattr("app.services.api_client.httpx.Client", fake_client)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.fetch_note_detail("alice", "note_001", access_token="access-token")

    assert isinstance(result, ObjectDetailResult)
    assert result.item is not None
    assert result.item["note_id"] == "note_001"
    assert result.error is None


def test_fetch_file_detail_success(monkeypatch) -> None:
    responses = {
        "/api/v1/dev/files/user/alice/file_001": DummyResponse(
            {
                "file_id": "file_001",
                "state": "active",
                "current_version": 1,
            }
        )
    }

    def fake_client(*args, **kwargs):
        return DummyClient(responses)

    monkeypatch.setattr("app.services.api_client.httpx.Client", fake_client)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.fetch_file_detail("alice", "file_001", access_token="access-token")

    assert isinstance(result, ObjectDetailResult)
    assert result.item is not None
    assert result.item["file_id"] == "file_001"
    assert result.error is None
