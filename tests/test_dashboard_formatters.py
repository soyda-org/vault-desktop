from app.ui.dashboard_formatters import (
    credential_list_label,
    file_list_label,
    format_credential_detail,
    format_credentials_items,
    format_file_detail,
    format_files_items,
    format_note_detail,
    format_notes_items,
    note_list_label,
)


def test_credential_list_label() -> None:
    text = credential_list_label(
        {
            "credential_id": "cred_001",
            "state": "active",
            "current_version": 1,
        }
    )

    assert "cred_001" in text
    assert "active" in text
    assert "v1" in text


def test_note_list_label() -> None:
    text = note_list_label(
        {
            "note_id": "note_001",
            "note_type": "note",
            "state": "active",
            "current_version": 1,
        }
    )

    assert "note_001" in text
    assert "note" in text
    assert "v1" in text


def test_file_list_label() -> None:
    text = file_list_label(
        {
            "file_id": "file_001",
            "state": "active",
            "current_version": 1,
        }
    )

    assert "file_001" in text
    assert "active" in text
    assert "v1" in text


def test_format_credentials_items_with_empty_list() -> None:
    text = format_credentials_items([])

    assert "Count: 0" in text
    assert "No credentials found." in text


def test_format_credentials_items_with_one_item() -> None:
    text = format_credentials_items(
        [
            {
                "credential_id": "cred_001",
                "state": "active",
                "current_version": 1,
                "updated_at": "2030-01-01T00:00:00Z",
            }
        ]
    )

    assert "cred_001" in text
    assert "Current version: 1" in text


def test_format_notes_items_with_one_item() -> None:
    text = format_notes_items(
        [
            {
                "note_id": "note_001",
                "note_type": "note",
                "state": "active",
                "current_version": 1,
                "updated_at": "2030-01-01T00:00:00Z",
            }
        ]
    )

    assert "note_001" in text
    assert "Type: note" in text


def test_format_files_items_with_one_item() -> None:
    text = format_files_items(
        [
            {
                "file_id": "file_001",
                "state": "active",
                "current_version": 1,
                "updated_at": "2030-01-01T00:00:00Z",
            }
        ]
    )

    assert "file_001" in text
    assert "Current version: 1" in text


def test_format_credential_detail() -> None:
    text = format_credential_detail(
        {
            "credential_id": "cred_001",
            "state": "active",
            "current_version": 1,
            "encrypted_payload": {"ciphertext_b64": "abc"},
            "encryption_header": {"nonce_b64": "xyz"},
        }
    )

    assert "Credential detail loaded successfully." in text
    assert "cred_001" in text
    assert "ciphertext_b64" in text


def test_format_note_detail() -> None:
    text = format_note_detail(
        {
            "note_id": "note_001",
            "note_type": "note",
            "state": "active",
            "encrypted_payload": {"ciphertext_b64": "abc"},
            "encryption_header": {"nonce_b64": "xyz"},
        }
    )

    assert "Note detail loaded successfully." in text
    assert "note_001" in text
    assert "ciphertext_b64" in text


def test_format_file_detail() -> None:
    text = format_file_detail(
        {
            "file_id": "file_001",
            "state": "active",
            "encrypted_manifest": {"ciphertext_b64": "abc"},
            "encryption_header": {"nonce_b64": "xyz"},
            "blobs": [{"object_key": "files/x.bin"}],
        }
    )

    assert "File detail loaded successfully." in text
    assert "file_001" in text
    assert "object_key" in text
