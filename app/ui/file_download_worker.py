from __future__ import annotations

from pathlib import Path
from threading import Event

from PySide6.QtCore import QObject, Signal, Slot

from app.services.desktop_service import VaultDesktopService
from app.services.file_crypto_bridge import (
    DecryptedFileDownload,
    UploadCancelledError,
    decrypt_downloaded_file,
)


class FileDownloadWorker(QObject):
    progress_text = Signal(str)
    progress_value = Signal(int)
    succeeded = Signal(object)
    canceled = Signal(str)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        *,
        desktop_service: VaultDesktopService,
        file_id: str,
        target_path: str,
        master_key_b64: str,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.desktop_service = desktop_service
        self.file_id = file_id
        self.target_path = target_path
        self.master_key_b64 = master_key_b64
        self._cancel_requested = Event()

    def request_cancel(self) -> None:
        self._cancel_requested.set()

    def _is_cancel_requested(self) -> bool:
        return self._cancel_requested.is_set()

    def _raise_if_cancelled(self) -> None:
        if self._is_cancel_requested():
            raise UploadCancelledError("Download canceled by user.")

    @Slot()
    def run(self) -> None:
        try:
            self.progress_value.emit(0)
            self.progress_text.emit("Fetching encrypted file detail...")
            self._raise_if_cancelled()

            file_detail_result = self.desktop_service.fetch_file_detail(self.file_id)
            if file_detail_result.error:
                raise RuntimeError(file_detail_result.error)

            file_detail = file_detail_result.item or {}
            blobs = list(file_detail.get("blobs", []))
            if not blobs:
                raise RuntimeError("File has no downloadable blobs.")

            self.progress_value.emit(10)
            self.progress_text.emit(
                "Encrypted file detail loaded.\n"
                f"File ID: {self.file_id}\n"
                f"Chunk count: {len(blobs)}"
            )
            self._raise_if_cancelled()

            chunk_payloads: list[dict] = []
            ordered_blobs = sorted(blobs, key=lambda item: int(item["chunk_index"]))
            total_chunks = len(ordered_blobs)

            for index, blob in enumerate(ordered_blobs, start=1):
                self._raise_if_cancelled()

                chunk_index = int(blob["chunk_index"])
                chunk_result = self.desktop_service.fetch_file_chunk(self.file_id, chunk_index)
                if chunk_result.error:
                    raise RuntimeError(chunk_result.error)

                chunk_payloads.append(chunk_result.item or {})

                progress = 10 + int((index / max(total_chunks, 1)) * 60)
                self.progress_value.emit(min(progress, 70))
                self.progress_text.emit(
                    "Downloading encrypted chunks...\n"
                    f"Chunk: {index}/{total_chunks}\n"
                    f"File ID: {self.file_id}"
                )

            self._raise_if_cancelled()

            self.progress_value.emit(80)
            self.progress_text.emit(
                "Decrypting and reassembling file locally...\n"
                f"File ID: {self.file_id}"
            )

            decrypted = decrypt_downloaded_file(
                file_detail=file_detail,
                chunk_payloads=chunk_payloads,
                master_key_b64=self.master_key_b64,
            )

            self._raise_if_cancelled()

            target = Path(self.target_path).expanduser()
            if not target.parent.exists():
                raise RuntimeError("Download target directory does not exist.")

            self.progress_value.emit(90)
            self.progress_text.emit(
                "Writing plaintext file to disk...\n"
                f"Target: {target}"
            )

            target.write_bytes(decrypted.plaintext_bytes)

            self.progress_value.emit(100)
            self.progress_text.emit(
                "File download completed.\n"
                f"Target: {target}"
            )
            self.succeeded.emit(
                {
                    "file_id": decrypted.file_id,
                    "file_version": decrypted.file_version,
                    "chunk_count": decrypted.chunk_count,
                    "bytes_written": len(decrypted.plaintext_bytes),
                    "target_path": str(target.resolve()),
                }
            )
        except UploadCancelledError as exc:
            self.progress_text.emit(str(exc))
            self.canceled.emit(str(exc))
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()
