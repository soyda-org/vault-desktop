import base64
import hashlib

from app.services.file_chunk_builder import build_chunks_from_bytes, build_chunks_from_path


def test_build_chunks_from_bytes_single_chunk() -> None:
    data = b"hello world"

    chunks = build_chunks_from_bytes(data, chunk_size_bytes=1024)

    assert len(chunks) == 1
    assert chunks[0]["ciphertext_b64"] == base64.b64encode(data).decode("ascii")
    assert chunks[0]["ciphertext_sha256_hex"] == hashlib.sha256(data).hexdigest()


def test_build_chunks_from_bytes_multiple_chunks() -> None:
    data = b"abcdefghij"

    chunks = build_chunks_from_bytes(data, chunk_size_bytes=4)

    assert len(chunks) == 3
    assert chunks[0]["ciphertext_b64"] == base64.b64encode(b"abcd").decode("ascii")
    assert chunks[1]["ciphertext_b64"] == base64.b64encode(b"efgh").decode("ascii")
    assert chunks[2]["ciphertext_b64"] == base64.b64encode(b"ij").decode("ascii")


def test_build_chunks_from_bytes_empty_input_returns_one_empty_chunk() -> None:
    chunks = build_chunks_from_bytes(b"", chunk_size_bytes=256)

    assert len(chunks) == 1
    assert chunks[0]["ciphertext_b64"] == ""
    assert chunks[0]["ciphertext_sha256_hex"] == hashlib.sha256(b"").hexdigest()


def test_build_chunks_from_bytes_rejects_non_positive_chunk_size() -> None:
    try:
        build_chunks_from_bytes(b"abc", chunk_size_bytes=0)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert str(exc) == "chunk_size_bytes must be greater than 0"


def test_build_chunks_from_path_reads_file_and_returns_metadata(tmp_path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"abcdef")

    result = build_chunks_from_path(file_path, chunk_size_bytes=2)

    assert result.source_path.endswith("sample.bin")
    assert result.file_size_bytes == 6
    assert result.chunk_size_bytes == 2
    assert len(result.chunks) == 3


def test_build_chunks_from_path_rejects_missing_file(tmp_path) -> None:
    missing = tmp_path / "missing.bin"

    try:
        build_chunks_from_path(missing, chunk_size_bytes=2)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "Not a regular file:" in str(exc)
