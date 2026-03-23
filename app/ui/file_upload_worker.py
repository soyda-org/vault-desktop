from __future__ import annotations

from threading import Event

from PySide6.QtCore import QObject, Signal, Slot

from app.services.desktop_service import VaultDesktopService
from app.services.file_crypto_bridge import (
    UploadCancelledError,
    build_encrypted_file_finalize_payload,
    inspect_plaintext_file,
)


class FileUploadWorker(QObject):
    progress_text = Signal(str)
    progress_value = Signal(int)
    payload_preview_ready = Signal(object, object, object)
    succeeded = Signal(object)
    canceled = Signal(str)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        *,
        desktop_service: VaultDesktopService,
        device_name: str,
        source_path: str,
        chunk_size_bytes: int,
        master_key_b64: str,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.desktop_service = desktop_service
        self.device_name = device_name
        self.source_path = source_path
        self.chunk_size_bytes = chunk_size_bytes
        self.master_key_b64 = master_key_b64
        self._cancel_requested = Event()

    def request_cancel(self) -> None:
        self._cancel_requested.set()

    def _is_cancel_requested(self) -> bool:
        return self._cancel_requested.is_set()

    def _raise_if_cancelled(self) -> None:
        if self._is_cancel_requested():
            raise UploadCancelledError("Upload canceled by user.")

    @Slot()
    def run(self) -> None:
        try:
            self.progress_value.emit(0)
            self.progress_text.emit("Inspecting local file...")
            self._raise_if_cancelled()

            inspection = inspect_plaintext_file(
                source_path=self.source_path,
                chunk_size_bytes=self.chunk_size_bytes,
            )

            self.progress_value.emit(10)
            self.progress_text.emit(
                "Local file inspected.\n"
                f"Path: {inspection.source_path}\n"
                f"Size: {inspection.file_size_bytes} bytes\n"
                f"Chunk count: {inspection.chunk_count}"
            )
            self._raise_if_cancelled()

            prepared_result = self.desktop_service.prepare_file(
                device_name=self.device_name,
                chunk_count=inspection.chunk_count,
            )
            if prepared_result.error:
                raise RuntimeError(prepared_result.error)

            prepared_file = prepared_result.item or {}

            self.progress_value.emit(20)
            self.progress_text.emit(
                "Server prepare completed.\n"
                f"Prepared file ID: {prepared_file.get('file_id', '<unknown>')}\n"
                f"Chunk count: {inspection.chunk_count}"
            )
            self._raise_if_cancelled()

            last_progress = -1

            def on_chunk_encrypted(current_chunk: int, total_chunks: int) -> None:
                nonlocal last_progress

                progress = 20 + int((current_chunk / max(total_chunks, 1)) * 60)
                if progress != last_progress:
                    last_progress = progress
                    self.progress_value.emit(min(progress, 80))

                milestone = max(1, total_chunks // 10)
                if (
                    current_chunk == 1
                    or current_chunk == total_chunks
                    or current_chunk % milestone == 0
                ):
                    self.progress_text.emit(
                        "Encrypting file locally...\n"
                        f"Chunk: {current_chunk}/{total_chunks}\n"
                        f"Source: {inspection.source_path}"
                    )

            finalize_payload = build_encrypted_file_finalize_payload(
                source_path=self.source_path,
                chunk_size_bytes=self.chunk_size_bytes,
                prepared_file=prepared_file,
                master_key_b64=self.master_key_b64,
                progress_callback=on_chunk_encrypted,
                should_cancel=self._is_cancel_requested,
            )

            self.payload_preview_ready.emit(
                finalize_payload.encrypted_manifest,
                finalize_payload.encryption_header,
                self._build_chunk_preview(finalize_payload),
            )

            self._raise_if_cancelled()

            self.progress_value.emit(90)
            self.progress_text.emit(
                "Finalizing encrypted upload...\n"
                f"File ID: {finalize_payload.file_id}\n"
                f"Chunk count: {len(finalize_payload.chunks)}"
            )

            result = self.desktop_service.finalize_file(
                device_name=self.device_name,
                file_id=finalize_payload.file_id,
                file_version=finalize_payload.file_version,
                encrypted_manifest=finalize_payload.encrypted_manifest,
                encryption_header=finalize_payload.encryption_header,
                chunks=finalize_payload.chunks,
            )
            if result.error:
                raise RuntimeError(result.error)

            item = result.item or {}
            self.progress_value.emit(100)
            self.progress_text.emit(
                "Encrypted file upload completed.\n"
                f"File ID: {item.get('file_id', finalize_payload.file_id)}"
            )
            self.succeeded.emit(item)
        except UploadCancelledError as exc:
            self.progress_text.emit(str(exc))
            self.canceled.emit(str(exc))
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()

    def _build_chunk_preview(self, finalize_payload) -> object:
        chunks = list(finalize_payload.chunks)
        should_render_full_chunks = (
            len(chunks) <= 8
            and all(len(str(chunk.get("ciphertext_b64", ""))) <= 2048 for chunk in chunks)
        )

        if should_render_full_chunks:
            return chunks

        preview_count = min(5, len(chunks))
        preview = []
        for chunk in chunks[:preview_count]:
            preview.append(
                {
                    "chunk_index": chunk.get("chunk_index"),
                    "object_key": chunk.get("object_key"),
                    "ciphertext_sha256_hex": chunk.get("ciphertext_sha256_hex"),
                    "ciphertext_b64_length": len(str(chunk.get("ciphertext_b64", ""))),
                }
            )

        return {
            "display_mode": "summary_only",
            "reason": "encrypted chunk payload too large for QTextEdit rendering",
            "file_id": finalize_payload.file_id,
            "file_version": finalize_payload.file_version,
            "total_plaintext_size": finalize_payload.total_plaintext_size,
            "chunk_size_bytes": finalize_payload.chunk_size_bytes,
            "chunk_count": len(chunks),
            "preview_count": preview_count,
            "preview": preview,
        }
