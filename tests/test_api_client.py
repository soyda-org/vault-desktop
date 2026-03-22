import httpx

from app.services.api_client import LoginPayload, RefreshPayload, VaultApiClient


class FakeResponse:
    def __init__(self, status_code: int, json_data: dict, text: str = "") -> None:
        self.status_code = status_code
        self._json_data = json_data
        self.text = text or str(json_data)

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "http://test")
            response = httpx.Response(self.status_code, request=request, json=self._json_data)
            raise httpx.HTTPStatusError("boom", request=request, response=response)


def test_login_parses_nested_session_and_tokens(monkeypatch) -> None:
    def fake_post(url, json=None, headers=None, timeout=None):
        return FakeResponse(
            200,
            {
                "user_id": "user_001",
                "device_id": "device_001",
                "session": {"session_id": "session_001"},
                "tokens": {
                    "access_token": "jwt-token",
                    "refresh_token": "refresh-token",
                    "token_type": "bearer",
                },
            },
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.login(
        LoginPayload(
            identifier="alice",
            password="strong-password",
            device_name="desktop-dev",
            platform="linux",
        )
    )

    assert result.error is None
    assert result.user_id == "user_001"
    assert result.session_id == "session_001"
    assert result.access_token == "jwt-token"
    assert result.refresh_token == "refresh-token"


def test_refresh_parses_rotated_tokens(monkeypatch) -> None:
    def fake_post(url, json=None, headers=None, timeout=None):
        return FakeResponse(
            200,
            {
                "session": {
                    "session_id": "session_002",
                    "user_id": "user_001",
                    "device_id": "device_001",
                },
                "tokens": {
                    "access_token": "jwt-token-2",
                    "refresh_token": "refresh-token-2",
                    "token_type": "bearer",
                },
            },
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.refresh(
        RefreshPayload(refresh_token="refresh-token-1")
    )

    assert result.error is None
    assert result.session_id == "session_002"
    assert result.access_token == "jwt-token-2"
    assert result.refresh_token == "refresh-token-2"


def test_fetch_credentials_returns_401_error_text(monkeypatch) -> None:
    def fake_get(url, headers=None, timeout=None):
        return FakeResponse(
            401,
            {"detail": "Invalid bearer token"},
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.fetch_credentials(access_token="bad-token")

    assert result.items == []
    assert result.status_code == 401
    assert result.error == "Invalid bearer token"


def test_create_credential_posts_authenticated_payload(monkeypatch) -> None:
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        return FakeResponse(
            201,
            {
                "credential_id": "cred_001",
                "user_id": "user_001",
                "state": "active",
                "current_version": 1,
                "encrypted_metadata": {"ciphertext_b64": "YWJj"},
                "encrypted_payload": {"ciphertext_b64": "ZGVm"},
                "encryption_header": {"nonce_b64": "bm9uY2U="},
                "created_by_device_id": "device_001",
                "created_at": "2030-01-01T00:00:00Z",
            },
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.create_credential(
        device_name="desktop-dev",
        encrypted_metadata={"ciphertext_b64": "YWJj"},
        encrypted_payload={"ciphertext_b64": "ZGVm"},
        encryption_header={"nonce_b64": "bm9uY2U="},
        access_token="access-token",
    )

    assert result.error is None
    assert result.status_code == 201
    assert result.item is not None
    assert result.item["credential_id"] == "cred_001"
    assert captured["url"] == "http://127.0.0.1:8000/api/v1/vault/credentials"
    assert captured["headers"]["Authorization"] == "Bearer access-token"
    assert captured["json"]["device_name"] == "desktop-dev"
