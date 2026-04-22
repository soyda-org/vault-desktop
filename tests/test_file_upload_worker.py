from types import SimpleNamespace

from app.services.api_client import ObjectCreateResult, ObjectDetailResult
from app.services.file_crypto_bridge import UploadCancelledError
from app.ui.file_upload_worker import FileUploadWorker


class FakeDesktopService:
    def __init__(self) -> None:
        self.prepare_calls: list[tuple[str, int]] = []
        self.upload_chunk_calls: list[tuple[str, str, int, int]] = []
        self.finalize_calls: list[tuple[str, str, int, str, int, int | None]] = []

    def prepare_file(self, *, device_name: str, chunk_count: int) -> ObjectDetailResult:
        self.prepare_calls.append((device_name, chunk_count))
        return ObjectDetailResult(
            item={
                "file_id": "file_001",
                "file_version": 1,
                "chunks": [
                    {"chunk_index": 0, "object_key": "files/file_001/v1/chunk_0000.bin"},
                    {"chunk_index": 1, "object_key": "files/file_001/v1/chunk_0001.bin"},
                ],
            },
            error=None,
            status_code=200,
        )

    def finalize_file(
        self,
        *,
        device_name: str,
        file_id: str,
        file_version: int,
        plaintext_filename: str,
        plaintext_size_bytes: int,
        encrypted_manifest: dict,
        encryption_header: dict,
        chunk_count: int | None = None,
        chunks: list[dict] | None = None,
    ) -> ObjectCreateResult:
        self.finalize_calls.append(
            (
                device_name,
                file_id,
                file_version,
                plaintext_filename,
                plaintext_size_bytes,
                chunk_count,
            )
        )
        return ObjectCreateResult(
            item={"file_id": file_id},
            error=None,
            status_code=201,
        )

    def upload_prepared_file_chunk(
        self,
        *,
        device_name: str,
        file_id: str,
        file_version: int,
        chunk_index: int,
        object_key: str,
        ciphertext_b64: str,
        ciphertext_sha256_hex: str,
    ) -> ObjectDetailResult:
        self.upload_chunk_calls.append((device_name, file_id, file_version, chunk_index))
        return ObjectDetailResult(
            item={
                "chunk_index": chunk_index,
                "object_key": object_key,
                "ciphertext_sha256_hex": ciphertext_sha256_hex,
            },
            error=None,
            status_code=200,
        )


def test_worker_emits_canceled_when_cancel_requested_before_run(monkeypatch) -> None:
    import app.ui.file_upload_worker as worker_module

    service = FakeDesktopService()

    monkeypatch.setattr(
        worker_module,
        "inspect_plaintext_file",
        lambda **kwargs: SimpleNamespace(
            source_path="/tmp/sample.bin",
            file_size_bytes=10,
            chunk_size_bytes=4,
            chunk_count=2,
        ),
    )

    worker = FileUploadWorker(
        desktop_service=service,
        device_name="desktop-dev",
        source_path="/tmp/sample.bin",
        chunk_size_bytes=4,
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

    assert canceled_messages == ["Upload canceled by user."]
    assert failed_messages == []
    assert finished_calls == ["done"]
    assert service.prepare_calls == []
    assert service.finalize_calls == []


def test_worker_emits_canceled_when_crypto_bridge_raises_cancel(monkeypatch) -> None:
    import app.ui.file_upload_worker as worker_module

    service = FakeDesktopService()

    monkeypatch.setattr(
        worker_module,
        "inspect_plaintext_file",
        lambda **kwargs: SimpleNamespace(
            source_path="/tmp/sample.bin",
            file_size_bytes=10,
            chunk_size_bytes=4,
            chunk_count=2,
        ),
    )

    def fake_build(**kwargs):
        raise UploadCancelledError("Upload canceled by user.")

    monkeypatch.setattr(worker_module, "build_encrypted_file_finalize_payload", fake_build)

    worker = FileUploadWorker(
        desktop_service=service,
        device_name="desktop-dev",
        source_path="/tmp/sample.bin",
        chunk_size_bytes=4,
        master_key_b64="S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s=",
    )

    canceled_messages: list[str] = []
    failed_messages: list[str] = []
    finished_calls: list[str] = []

    worker.canceled.connect(canceled_messages.append)
    worker.failed.connect(failed_messages.append)
    worker.finished.connect(lambda: finished_calls.append("done"))

    worker.run()

    assert canceled_messages == ["Upload canceled by user."]
    assert failed_messages == []
    assert finished_calls == ["done"]
    assert service.prepare_calls == [("desktop-dev", 2)]
    assert service.finalize_calls == []
