from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from vault_crypto.encoding import b64decode_text, b64encode_bytes
from vault_crypto.envelopes import (
    EncryptedPayloadEnvelope,
    EncryptionHeader,
    decrypt_payload,
    encrypt_payload,
)
from vault_crypto.files import EncryptedFileManifest, FileChunkDescriptor
from vault_crypto.keys import HkdfKeyContext, KeyPurpose, derive_hkdf_subkey
from vault_crypto.serialization import dumps_canonical_bytes, loads_json


class UploadCancelledError(RuntimeError):
    pass


@dataclass(frozen=True)
class PlaintextFileInspection:
    source_path: str
    file_size_bytes: int
    chunk_size_bytes: int
    chunk_count: int


@dataclass(frozen=True)
class EncryptedFileFinalizePayload:
    source_path: str
    plaintext_filename: str
    file_id: str
    file_version: int
    total_plaintext_size: int
    chunk_size_bytes: int
    encrypted_manifest: dict
    encryption_header: dict
    chunks: list[dict]


@dataclass(frozen=True)
class DecryptedFileDownload:
    file_id: str
    file_version: int
    total_plaintext_size: int
    chunk_size_bytes: int
    chunk_count: int
    plaintext_bytes: bytes


def parse_dev_aes256_key_b64(master_key_b64: str) -> bytes:
    key = b64decode_text(master_key_b64)
    if len(key) != 32:
        raise ValueError("master_key_b64 must decode to exactly 32 bytes")
    return key


def inspect_plaintext_file(
    *,
    source_path: str | Path,
    chunk_size_bytes: int,
) -> PlaintextFileInspection:
    if chunk_size_bytes <= 0:
        raise ValueError("chunk_size_bytes must be greater than 0")

    path = Path(source_path).expanduser()
    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")

    size = path.stat().st_size
    chunk_count = max(1, (size + chunk_size_bytes - 1) // chunk_size_bytes)

    return PlaintextFileInspection(
        source_path=str(path.resolve()),
        file_size_bytes=size,
        chunk_size_bytes=chunk_size_bytes,
        chunk_count=chunk_count,
    )


def build_encrypted_file_finalize_payload(
    *,
    source_path: str | Path,
    chunk_size_bytes: int,
    prepared_file: dict,
    master_key_b64: str,
    progress_callback: Callable[[int, int], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> EncryptedFileFinalizePayload:
    if chunk_size_bytes <= 0:
        raise ValueError("chunk_size_bytes must be greater than 0")

    path = Path(source_path).expanduser()
    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")

    total_plaintext_size = path.stat().st_size
    expected_chunk_count = max(1, (total_plaintext_size + chunk_size_bytes - 1) // chunk_size_bytes)

    master_key = parse_dev_aes256_key_b64(master_key_b64)

    file_id = str(prepared_file["file_id"])
    file_version = int(prepared_file["file_version"])
    prepared_chunks = list(prepared_file.get("chunks", []))

    if expected_chunk_count != len(prepared_chunks):
        raise ValueError(
            f"Prepared chunk count mismatch: expected {expected_chunk_count}, "
            f"got {len(prepared_chunks)}"
        )

    def raise_if_cancelled() -> None:
        if should_cancel is not None and should_cancel():
            raise UploadCancelledError("Upload canceled by user.")

    raise_if_cancelled()

    file_master_key = derive_hkdf_subkey(
        master_key=master_key,
        context=HkdfKeyContext(
            purpose=KeyPurpose.FILE_MASTER,
            object_type="file",
            object_id=file_id,
            object_version=file_version,
        ),
    )

    finalize_chunks: list[dict] = []
    manifest_chunks: list[FileChunkDescriptor] = []
    total_chunks = len(prepared_chunks)

    with path.open("rb") as handle:
        if total_plaintext_size == 0:
            chunk_iter = [b""]
        else:
            chunk_iter = iter(lambda: handle.read(chunk_size_bytes), b"")

        for prepared_chunk, plaintext_chunk in zip(prepared_chunks, chunk_iter, strict=True):
            raise_if_cancelled()

            chunk_index = int(prepared_chunk["chunk_index"])
            object_key = str(prepared_chunk["object_key"])

            chunk_key = derive_hkdf_subkey(
                master_key=file_master_key,
                context=HkdfKeyContext(
                    purpose=KeyPurpose.FILE_CHUNK,
                    object_type="file_chunk",
                    object_id=f"{file_id}:{chunk_index}",
                    object_version=file_version,
                ),
            )

            chunk_envelope = encrypt_payload(
                key=chunk_key,
                object_type="file_chunk",
                object_id=f"{file_id}:{chunk_index}",
                object_version=file_version,
                plaintext=plaintext_chunk,
            )
            chunk_envelope_bytes = dumps_canonical_bytes(chunk_envelope.to_dict())
            chunk_sha256_hex = hashlib.sha256(chunk_envelope_bytes).hexdigest()

            finalize_chunks.append(
                {
                    "chunk_index": chunk_index,
                    "object_key": object_key,
                    "ciphertext_b64": b64encode_bytes(chunk_envelope_bytes),
                    "ciphertext_sha256_hex": chunk_sha256_hex,
                }
            )

            manifest_chunks.append(
                FileChunkDescriptor(
                    chunk_index=chunk_index,
                    object_key=object_key,
                    ciphertext_size_bytes=len(chunk_envelope_bytes),
                    ciphertext_sha256_hex=chunk_sha256_hex,
                )
            )

            if progress_callback is not None:
                progress_callback(chunk_index + 1, total_chunks)

    raise_if_cancelled()

    manifest = EncryptedFileManifest(
        file_id=file_id,
        file_version=file_version,
        total_plaintext_size=total_plaintext_size,
        chunk_size=chunk_size_bytes,
        chunks=tuple(manifest_chunks),
    )
    manifest_plaintext = dumps_canonical_bytes(manifest.to_dict())

    raise_if_cancelled()

    manifest_envelope = encrypt_payload(
        key=file_master_key,
        object_type="file_manifest",
        object_id=file_id,
        object_version=file_version,
        plaintext=manifest_plaintext,
    )

    raise_if_cancelled()

    return EncryptedFileFinalizePayload(
        source_path=str(path.resolve()),
        plaintext_filename=path.name,
        file_id=file_id,
        file_version=file_version,
        total_plaintext_size=total_plaintext_size,
        chunk_size_bytes=chunk_size_bytes,
        encrypted_manifest={"ciphertext_b64": manifest_envelope.ciphertext_b64},
        encryption_header=manifest_envelope.header.to_dict(),
        chunks=finalize_chunks,
    )


def decrypt_downloaded_file(
    *,
    file_detail: dict,
    chunk_payloads: list[dict],
    master_key_b64: str,
) -> DecryptedFileDownload:
    file_id = str(file_detail["file_id"])
    file_version = int(file_detail["current_version"])

    manifest_ciphertext_b64 = str(file_detail["encrypted_manifest"]["ciphertext_b64"])
    manifest_header = EncryptionHeader.from_dict(file_detail["encryption_header"])

    if manifest_header.object_type != "file_manifest":
        raise ValueError("Unexpected manifest object_type")
    if manifest_header.object_id != file_id:
        raise ValueError("Manifest object_id does not match file_id")
    if manifest_header.object_version != file_version:
        raise ValueError("Manifest object_version does not match current_version")

    master_key = parse_dev_aes256_key_b64(master_key_b64)

    file_master_key = derive_hkdf_subkey(
        master_key=master_key,
        context=HkdfKeyContext(
            purpose=KeyPurpose.FILE_MASTER,
            object_type="file",
            object_id=file_id,
            object_version=file_version,
        ),
    )

    manifest_plaintext = decrypt_payload(
        key=file_master_key,
        envelope=EncryptedPayloadEnvelope(
            header=manifest_header,
            ciphertext_b64=manifest_ciphertext_b64,
        ),
    )
    manifest = EncryptedFileManifest.from_dict(loads_json(manifest_plaintext))

    if manifest.file_id != file_id:
        raise ValueError("Manifest file_id mismatch")
    if manifest.file_version != file_version:
        raise ValueError("Manifest file_version mismatch")

    payloads_by_index: dict[int, dict] = {}
    for chunk_payload in chunk_payloads:
        chunk_index = int(chunk_payload["chunk_index"])
        if chunk_index in payloads_by_index:
            raise ValueError("Duplicate downloaded chunk_index")
        payloads_by_index[chunk_index] = chunk_payload

    plaintext_parts: list[bytes] = []

    for descriptor in manifest.chunks:
        chunk_payload = payloads_by_index.get(descriptor.chunk_index)
        if chunk_payload is None:
            raise ValueError("Missing downloaded chunk payload")

        object_key = str(chunk_payload["object_key"])
        if object_key != descriptor.object_key:
            raise ValueError("Downloaded chunk object_key mismatch")

        ciphertext_b64 = str(chunk_payload["ciphertext_b64"])
        ciphertext_bytes = b64decode_text(ciphertext_b64)

        if len(ciphertext_bytes) != descriptor.ciphertext_size_bytes:
            raise ValueError("Downloaded chunk size mismatch")

        declared_size = int(chunk_payload["ciphertext_size_bytes"])
        if declared_size != descriptor.ciphertext_size_bytes:
            raise ValueError("Declared downloaded chunk size mismatch")

        actual_sha256_hex = hashlib.sha256(ciphertext_bytes).hexdigest()
        if actual_sha256_hex != descriptor.ciphertext_sha256_hex:
            raise ValueError("Ciphertext SHA-256 mismatch for downloaded chunk")

        declared_sha256_hex = str(chunk_payload["ciphertext_sha256_hex"])
        if declared_sha256_hex != descriptor.ciphertext_sha256_hex:
            raise ValueError("Declared downloaded chunk SHA-256 mismatch")

        chunk_envelope = EncryptedPayloadEnvelope.from_dict(loads_json(ciphertext_bytes))

        expected_chunk_object_id = f"{manifest.file_id}:{descriptor.chunk_index}"
        if chunk_envelope.header.object_type != "file_chunk":
            raise ValueError("Unexpected file chunk object_type")
        if chunk_envelope.header.object_id != expected_chunk_object_id:
            raise ValueError("Unexpected file chunk object_id")
        if chunk_envelope.header.object_version != manifest.file_version:
            raise ValueError("Unexpected file chunk object_version")

        chunk_key = derive_hkdf_subkey(
            master_key=file_master_key,
            context=HkdfKeyContext(
                purpose=KeyPurpose.FILE_CHUNK,
                object_type="file_chunk",
                object_id=expected_chunk_object_id,
                object_version=manifest.file_version,
            ),
        )

        plaintext_parts.append(
            decrypt_payload(
                key=chunk_key,
                envelope=chunk_envelope,
            )
        )

    plaintext_bytes = b"".join(plaintext_parts)

    if len(plaintext_bytes) != manifest.total_plaintext_size:
        raise ValueError("Plaintext size mismatch after file reassembly")

    return DecryptedFileDownload(
        file_id=manifest.file_id,
        file_version=manifest.file_version,
        total_plaintext_size=manifest.total_plaintext_size,
        chunk_size_bytes=manifest.chunk_size,
        chunk_count=len(manifest.chunks),
        plaintext_bytes=plaintext_bytes,
    )
