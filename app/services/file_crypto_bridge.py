from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from vault_crypto.encoding import b64decode_text, b64encode_bytes
from vault_crypto.envelopes import encrypt_payload
from vault_crypto.files import EncryptedFileManifest, FileChunkDescriptor
from vault_crypto.keys import HkdfKeyContext, KeyPurpose, derive_hkdf_subkey
from vault_crypto.serialization import dumps_canonical_bytes


@dataclass(frozen=True)
class PlaintextFileInspection:
    source_path: str
    file_size_bytes: int
    chunk_size_bytes: int
    chunk_count: int


@dataclass(frozen=True)
class EncryptedFileFinalizePayload:
    source_path: str
    file_id: str
    file_version: int
    total_plaintext_size: int
    chunk_size_bytes: int
    encrypted_manifest: dict
    encryption_header: dict
    chunks: list[dict]


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

    manifest = EncryptedFileManifest(
        file_id=file_id,
        file_version=file_version,
        total_plaintext_size=total_plaintext_size,
        chunk_size=chunk_size_bytes,
        chunks=tuple(manifest_chunks),
    )
    manifest_plaintext = dumps_canonical_bytes(manifest.to_dict())

    manifest_envelope = encrypt_payload(
        key=file_master_key,
        object_type="file_manifest",
        object_id=file_id,
        object_version=file_version,
        plaintext=manifest_plaintext,
    )

    return EncryptedFileFinalizePayload(
        source_path=str(path.resolve()),
        file_id=file_id,
        file_version=file_version,
        total_plaintext_size=total_plaintext_size,
        chunk_size_bytes=chunk_size_bytes,
        encrypted_manifest={"ciphertext_b64": manifest_envelope.ciphertext_b64},
        encryption_header=manifest_envelope.header.to_dict(),
        chunks=finalize_chunks,
    )
