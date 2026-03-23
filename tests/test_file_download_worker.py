from pathlib import Path
from types import SimpleNamespace

from app.services.api_client import ObjectDetailResult
from app.ui.file_download_worker import FileDownloadWorker


class FakeDesktopService:
    def __init__(self) -> None:
        self.detail_calls: list[str] = []
        self.chunk_calls: list[tuple[str, int]] = []

    def fetch_file_detail(self, file_id: str) -> ObjectDetailResult:
        self.detail_calls.append(file_id)
        return ObjectDetailResult(
            item={
                "file_id": file_id,
                "current_version": 1,
                "encrypted_manifest": {"ciphertext_b64": "manifest"},
                "encryption_header": {
                    "alg": "AES-256-GCM",
                    "object_type": "file_manifest",
                    "object_id": file_id,
                    "object_version": 1,
                    "nonce_b64": "bm9uY2U=",
                },
                "blobs": [
                    {
                        "chunk_index": 0,
                        "object_key": f"files/{file_id}/v1/chunk_0000.bin",
                        "ciphertext_size_bytes": 4,
                        "ciphertext_sha256_hex": "a" * 64,
                    },
                    {
                        "chunk_index": 1,
                        "object_key": f"files/{file_id}/v1/chunk_0001.bin",
                        "ciphertext_size_bytes": 4,
                        "ciphertext_sha256_hex": "b" * 64,
                    },
                ],
            },
            error=None,
            status_code=200,
        )

    def fetch_file_chunk(self, file_id: str, chunk_index: int) -> ObjectDetailResult:
        self.chunk_calls.append((file_id, chunk_index))
        return ObjectDetailResult(
            item={
                "chunk_index": chunk_index,
                "object_key": f"files/{file_id}/v1/chunk_{chunk_index:04d}.bin",
                "ciphertext_b64": "ZmFrZQ==",
                "ciphertext_sha256_hex": ("a" * 64) if chunk_index == 0 else ("b" * 64),
                "ciphertext_size_bytes": 4,
            },
            error=None,
            status_code=200,
        )


def test_download_worker_success_writes_file(monkeypatch, tmp_path) -> None:
    import app.ui.file_download_worker as worker_module

    service = FakeDesktopService()
    target_path = tmp_path / "downloaded.bin"

    monkeypatch.setattr(
        worker_module,
        "decrypt_downloaded_file",
        lambda **kwargs: SimpleNamespace(
            file_id="file_001",
            file_version=1,
            chunk_count=2,
            plaintext_bytes=b"hello world",
        ),
    )

    worker = FileDownloadWorker(
        desktop_service=service,
        file_id="file_001",
        target_path=str(target_path),
        master_key_b64="S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s=",
    )

    succeeded_items: list[dict] = []
    failed_messages: list[str] = []
    canceled_messages: list[str] = []
    finished_calls: list[str] = []

    worker.succeeded.connect(succeeded_items.append)
    worker.failed.connect(failed_messages.append)
    worker.canceled.connect(canceled_messages.append)
    worker.finished.connect(lambda: finished_calls.append("done"))

    worker.run()

    assert failed_messages == []
    assert canceled_messages == []
    assert finished_calls == ["done"]
    assert service.detail_calls == ["file_001"]
    assert service.chunk_calls == [("file_001", 0), ("file_001", 1)]
    assert target_path.read_bytes() == b"hello world"
    assert succeeded_items[0]["file_id"] == "file_001"
    assert succeeded_items[0]["bytes_written"] == 11


def test_download_worker_cancels_before_run(monkeypatch, tmp_path) -> None:
    import app.ui.file_download_worker as worker_module

    service = FakeDesktopService()
    target_path = tmp_path / "downloaded.bin"

    monkeypatch.setattr(
        worker_module,
        "decrypt_downloaded_file",
        lambda **kwargs: SimpleNamespace(
            file_id="file_001",
            file_version=1,
            chunk_count=2,
            plaintext_bytes=b"hello world",
        ),
    )

    worker = FileDownloadWorker(
        desktop_service=service,
        file_id="file_001",
        target_path=str(target_path),
        master_key_b64="S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s=",
    )

    canceled_messages: list[str] = []
    failed_messages: list[str] = []
    finished_calls: list[str] = []

    worker.canceled.connect(canceled_messages.append)
    worker.failed.connect(failed_messages.append)
    worker.finished.connect(lambda: finished_calls.append("done"))

    worker.request_cancel()
    worker.run()

    assert canceled_messages == ["Download canceled by user."]
    assert failed_messages == []
    assert finished_calls == ["done"]
    assert service.detail_calls == []
    assert service.chunk_calls == []
    assert not target_path.exists()
