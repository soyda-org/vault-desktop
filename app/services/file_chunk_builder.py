from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path


_EMPTY_SHA256_HEX = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class ChunkBuildResult:
    source_path: str
    file_size_bytes: int
    chunk_size_bytes: int
    chunks: list[dict[str, str]]


def build_chunks_from_bytes(data: bytes, chunk_size_bytes: int) -> list[dict[str, str]]:
    if chunk_size_bytes <= 0:
        raise ValueError("chunk_size_bytes must be greater than 0")

    if not data:
        return [
            {
                "ciphertext_b64": "",
                "ciphertext_sha256_hex": _EMPTY_SHA256_HEX,
            }
        ]

    chunks: list[dict[str, str]] = []
    for offset in range(0, len(data), chunk_size_bytes):
        chunk_bytes = data[offset : offset + chunk_size_bytes]
        chunks.append(
            {
                "ciphertext_b64": base64.b64encode(chunk_bytes).decode("ascii"),
                "ciphertext_sha256_hex": hashlib.sha256(chunk_bytes).hexdigest(),
            }
        )
    return chunks


def build_chunks_from_path(path: str | Path, chunk_size_bytes: int) -> ChunkBuildResult:
    file_path = Path(path).expanduser()

    if not file_path.is_file():
        raise ValueError(f"Not a regular file: {file_path}")

    data = file_path.read_bytes()

    return ChunkBuildResult(
        source_path=str(file_path.resolve()),
        file_size_bytes=len(data),
        chunk_size_bytes=chunk_size_bytes,
        chunks=build_chunks_from_bytes(data, chunk_size_bytes=chunk_size_bytes),
    )
