import base64

from vault_crypto.serialization import loads_json

from app.services.file_crypto_bridge import (
    UploadCancelledError,
    build_encrypted_file_finalize_payload,
    inspect_plaintext_file,
    parse_dev_aes256_key_b64,
)


def test_parse_dev_aes256_key_b64_requires_32_bytes() -> None:
    good = base64.b64encode(b"K" * 32).decode("ascii")
    assert parse_dev_aes256_key_b64(good) == b"K" * 32

    bad = base64.b64encode(b"K" * 16).decode("ascii")
    try:
        parse_dev_aes256_key_b64(bad)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert str(exc) == "master_key_b64 must decode to exactly 32 bytes"


def test_inspect_plaintext_file_returns_chunk_count(tmp_path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"abcdefghij")

    result = inspect_plaintext_file(source_path=path, chunk_size_bytes=4)

    assert result.source_path.endswith("sample.bin")
    assert result.file_size_bytes == 10
    assert result.chunk_size_bytes == 4
    assert result.chunk_count == 3


def test_build_encrypted_file_finalize_payload_returns_real_encrypted_payloads(tmp_path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"abcdefghij")

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

    result = build_encrypted_file_finalize_payload(
        source_path=path,
        chunk_size_bytes=4,
        prepared_file=prepared,
        master_key_b64=master_key_b64,
    )

    assert result.file_id == "file_001"
    assert result.file_version == 1
    assert result.total_plaintext_size == 10
    assert result.chunk_size_bytes == 4
    assert len(result.chunks) == 3

    assert result.encryption_header["object_type"] == "file_manifest"
    assert result.encryption_header["object_id"] == "file_001"
    assert "ciphertext_b64" in result.encrypted_manifest

    first_chunk = result.chunks[0]
    assert first_chunk["object_key"] == "files/file_001/v1/chunk_0000.bin"
    assert first_chunk["ciphertext_b64"] != base64.b64encode(b"abcd").decode("ascii")

    chunk_envelope_bytes = base64.b64decode(first_chunk["ciphertext_b64"])
    chunk_envelope = loads_json(chunk_envelope_bytes)
    assert chunk_envelope["header"]["object_type"] == "file_chunk"
    assert chunk_envelope["header"]["object_id"] == "file_001:0"


def test_build_encrypted_file_finalize_payload_rejects_prepared_chunk_count_mismatch(tmp_path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"abcdefghij")

    master_key_b64 = base64.b64encode(b"K" * 32).decode("ascii")
    prepared = {
        "file_id": "file_001",
        "file_version": 1,
        "chunks": [
            {"chunk_index": 0, "object_key": "files/file_001/v1/chunk_0000.bin"},
        ],
    }

    try:
        build_encrypted_file_finalize_payload(
            source_path=path,
            chunk_size_bytes=4,
            prepared_file=prepared,
            master_key_b64=master_key_b64,
        )
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "Prepared chunk count mismatch:" in str(exc)


def test_build_encrypted_file_finalize_payload_reports_progress_per_chunk(tmp_path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"abcdefghij")

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

    progress_calls: list[tuple[int, int]] = []

    build_encrypted_file_finalize_payload(
        source_path=path,
        chunk_size_bytes=4,
        prepared_file=prepared,
        master_key_b64=master_key_b64,
        progress_callback=lambda current, total: progress_calls.append((current, total)),
    )

    assert progress_calls == [(1, 3), (2, 3), (3, 3)]


def test_build_encrypted_file_finalize_payload_can_cancel_before_first_chunk(tmp_path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"abcdefghij")

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

    try:
        build_encrypted_file_finalize_payload(
            source_path=path,
            chunk_size_bytes=4,
            prepared_file=prepared,
            master_key_b64=master_key_b64,
            should_cancel=lambda: True,
        )
        assert False, "Expected UploadCancelledError"
    except UploadCancelledError as exc:
        assert str(exc) == "Upload canceled by user."


def test_build_encrypted_file_finalize_payload_can_cancel_between_chunks(tmp_path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"abcdefghij")

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

    progress_calls: list[tuple[int, int]] = []

    try:
        build_encrypted_file_finalize_payload(
            source_path=path,
            chunk_size_bytes=4,
            prepared_file=prepared,
            master_key_b64=master_key_b64,
            progress_callback=lambda current, total: progress_calls.append((current, total)),
            should_cancel=lambda: len(progress_calls) >= 1,
        )
        assert False, "Expected UploadCancelledError"
    except UploadCancelledError as exc:
        assert str(exc) == "Upload canceled by user."

    assert progress_calls == [(1, 3)]
