import base64

import httpx

from app.services.api_client import LoginPayload, ObjectDetailResult, VaultApiClient
from app.services.desktop_service import VaultDesktopService
from app.services.file_crypto_bridge import (
    build_encrypted_file_finalize_payload,
    decrypt_downloaded_file,
)


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


def test_api_client_fetch_file_chunk_gets_authenticated_payload(monkeypatch) -> None:
    captured = {}

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["timeout"] = timeout
        return FakeResponse(
            200,
            {
                "chunk_index": 0,
                "object_key": "files/file_001/v1/chunk_0000.bin",
                "ciphertext_b64": "ZmFrZQ==",
                "ciphertext_sha256_hex": "a" * 64,
                "ciphertext_size_bytes": 4,
            },
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    client = VaultApiClient("http://127.0.0.1:8000")
    result = client.fetch_file_chunk(
        "file_001",
        0,
        access_token="access-token",
    )

    assert result.error is None
    assert result.item is not None
    assert result.item["chunk_index"] == 0
    assert captured["url"] == "http://127.0.0.1:8000/api/v1/vault/files/file_001/chunks/0"
    assert captured["headers"]["Authorization"] == "Bearer access-token"


class FakeApiClient:
    def login(self, payload):
        from app.services.api_client import LoginResult

        return LoginResult(
            user_id="user_001",
            device_id="device_001",
            session_id="session_001",
            access_token="access-token-1",
            refresh_token="refresh-token-1",
            token_type="bearer",
            error=None,
            status_code=200,
        )

    def refresh(self, payload):
        from app.services.api_client import RefreshResult

        return RefreshResult(
            user_id="user_001",
            device_id="device_001",
            session_id="session_001",
            access_token="access-token-2",
            refresh_token="refresh-token-2",
            token_type="bearer",
            error=None,
            status_code=200,
        )


class FakeVaultGateway:
    def __init__(self) -> None:
        self.calls = []

    def fetch_file_chunk(self, session, file_id, chunk_index):
        self.calls.append(("fetch_file_chunk", file_id, chunk_index, session.access_token))
        return ObjectDetailResult(
            item={
                "chunk_index": chunk_index,
                "object_key": f"files/{file_id}/v1/chunk_{chunk_index:04d}.bin",
                "ciphertext_b64": "ZmFrZQ==",
                "ciphertext_sha256_hex": "a" * 64,
                "ciphertext_size_bytes": 4,
            },
            error=None,
            status_code=200,
        )


def test_desktop_service_fetch_file_chunk_uses_gateway_with_current_session() -> None:
    gateway = FakeVaultGateway()
    service = VaultDesktopService(api_client=FakeApiClient(), vault_gateway=gateway)
    service.login(
        identifier="alice",
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )

    result = service.fetch_file_chunk("file_001", 0)

    assert result.error is None
    assert result.item is not None
    assert result.item["chunk_index"] == 0
    assert gateway.calls == [("fetch_file_chunk", "file_001", 0, "access-token-1")]


def test_decrypt_downloaded_file_roundtrip(tmp_path) -> None:
    sample_path = tmp_path / "sample.bin"
    sample_path.write_bytes(b"abcdefghij")

    master_key_b64 = base64.b64encode(b"K" * 32).decode("ascii")
    prepared = {
        "file_id": "file_001",
        "file_version": 1,
        "chunks": [
            {"chunk_index": 0, "object_key": "files/file_001/v1/chunk_0000.bin"},
            {"chunk_index": 1, "object_key": "files/file_001/v1/chunk_0001.bin"},
            {"chunk_index": 2, "object_key": "files/file_001/v1/chunk_0002.bin"},
        ],
    }

    streamed_chunks: list[dict] = []
    finalize_payload = build_encrypted_file_finalize_payload(
        source_path=sample_path,
        chunk_size_bytes=4,
        prepared_file=prepared,
        master_key_b64=master_key_b64,
        progress_callback=lambda _current, _total, chunk: streamed_chunks.append(chunk),
    )

    file_detail = {
        "file_id": finalize_payload.file_id,
        "current_version": finalize_payload.file_version,
        "encrypted_manifest": finalize_payload.encrypted_manifest,
        "encryption_header": finalize_payload.encryption_header,
    }
    chunk_payloads = [
        {
            "chunk_index": chunk["chunk_index"],
            "object_key": chunk["object_key"],
            "ciphertext_b64": chunk["ciphertext_b64"],
            "ciphertext_sha256_hex": chunk["ciphertext_sha256_hex"],
            "ciphertext_size_bytes": len(base64.b64decode(chunk["ciphertext_b64"])),
        }
        for chunk in streamed_chunks
    ]

    result = decrypt_downloaded_file(
        file_detail=file_detail,
        chunk_payloads=chunk_payloads,
        master_key_b64=master_key_b64,
    )

    assert result.file_id == "file_001"
    assert result.file_version == 1
    assert result.chunk_count == 3
    assert result.total_plaintext_size == 10
    assert result.plaintext_bytes == b"abcdefghij"


def test_decrypt_downloaded_file_rejects_chunk_sha_mismatch(tmp_path) -> None:
    sample_path = tmp_path / "sample.bin"
    sample_path.write_bytes(b"abcdefghij")

    master_key_b64 = base64.b64encode(b"K" * 32).decode("ascii")
    prepared = {
        "file_id": "file_001",
        "file_version": 1,
        "chunks": [
            {"chunk_index": 0, "object_key": "files/file_001/v1/chunk_0000.bin"},
            {"chunk_index": 1, "object_key": "files/file_001/v1/chunk_0001.bin"},
            {"chunk_index": 2, "object_key": "files/file_001/v1/chunk_0002.bin"},
        ],
    }

    streamed_chunks: list[dict] = []
    finalize_payload = build_encrypted_file_finalize_payload(
        source_path=sample_path,
        chunk_size_bytes=4,
        prepared_file=prepared,
        master_key_b64=master_key_b64,
        progress_callback=lambda _current, _total, chunk: streamed_chunks.append(chunk),
    )

    bad_chunk_payloads = [
        {
            "chunk_index": chunk["chunk_index"],
            "object_key": chunk["object_key"],
            "ciphertext_b64": chunk["ciphertext_b64"],
            "ciphertext_sha256_hex": ("0" * 64) if chunk["chunk_index"] == 0 else chunk["ciphertext_sha256_hex"],
            "ciphertext_size_bytes": len(base64.b64decode(chunk["ciphertext_b64"])),
        }
        for chunk in streamed_chunks
    ]

    try:
        decrypt_downloaded_file(
            file_detail={
                "file_id": finalize_payload.file_id,
                "current_version": finalize_payload.file_version,
                "encrypted_manifest": finalize_payload.encrypted_manifest,
                "encryption_header": finalize_payload.encryption_header,
            },
            chunk_payloads=bad_chunk_payloads,
            master_key_b64=master_key_b64,
        )
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert str(exc) == "Declared downloaded chunk SHA-256 mismatch"
