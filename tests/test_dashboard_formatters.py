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
            "plaintext_app_name": "GitHub",
            "plaintext_username": "alice",
            "state": "active",
            "current_version": 1,
        }
    )

    assert "GitHub" in text
    assert "alice" in text
    assert "·" in text


def test_note_list_label() -> None:
    text = note_list_label(
        {
            "note_id": "note_001",
            "plaintext_title": "todo",
            "note_type": "note",
            "state": "active",
            "current_version": 1,
        }
    )

    assert "todo" in text
    assert "note" in text
    assert "v1" in text


def test_file_list_label() -> None:
    text = file_list_label(
        {
            "plaintext_filename": "archive.zip",
            "plaintext_size_bytes": 33333,
        }
    )

    assert text == "archive.zip | 33 333 B"


def test_format_credentials_items_with_empty_list() -> None:
    text = format_credentials_items([])

    assert "Count: 0" in text
    assert "No credentials found." in text


def test_format_credentials_items_with_one_item() -> None:
    text = format_credentials_items(
        [
            {
                "credential_id": "cred_001",
                "plaintext_app_name": "GitHub",
                "plaintext_username": "alice",
                "state": "active",
                "current_version": 1,
                "updated_at": "2030-01-01T00:00:00Z",
            }
        ]
    )

    assert "GitHub" in text
    assert "alice" in text
    assert "Current version: 1" in text


def test_format_notes_items_with_one_item() -> None:
    text = format_notes_items(
        [
            {
                "note_id": "note_001",
                "plaintext_title": "todo",
                "note_type": "note",
                "state": "active",
                "current_version": 1,
                "updated_at": "2030-01-01T00:00:00Z",
            }
        ]
    )

    assert "todo" in text
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
            "plaintext_app_name": "GitHub",
            "plaintext_username": "alice",
            "state": "active",
            "current_version": 1,
            "encrypted_payload": {"ciphertext_b64": "abc"},
            "encryption_header": {"nonce_b64": "xyz"},
        }
    )

    assert "Credential detail loaded successfully." in text
    assert "GitHub" in text
    assert "alice" in text
    assert "ciphertext_b64" not in text


def test_format_note_detail() -> None:
    text = format_note_detail(
        {
            "note_id": "note_001",
            "plaintext_title": "todo",
            "note_type": "note",
            "state": "active",
            "encrypted_payload": {"ciphertext_b64": "abc"},
            "encryption_header": {"nonce_b64": "xyz"},
        }
    )

    assert "Note detail loaded successfully." in text
    assert "todo" in text
    assert "ciphertext_b64" not in text


def test_format_file_detail() -> None:
    text = format_file_detail(
        {
            "file_id": "file_001",
            "plaintext_filename": "archive.zip",
            "plaintext_size_bytes": 1234,
            "state": "active",
            "encrypted_manifest": {"ciphertext_b64": "abc"},
            "encryption_header": {"nonce_b64": "xyz"},
            "blobs": [{"object_key": "files/x.bin"}],
        }
    )

    assert "File detail loaded successfully." in text
    assert "archive.zip" in text
    assert "Size: 1 234" in text
    assert "object_key" not in text


def test_format_credential_detail_includes_plaintext_sections_when_available() -> None:
    text = format_credential_detail(
        {
            "credential_id": "cred_001",
            "plaintext_app_name": "Personal",
            "state": "active",
            "current_version": 1,
            "encrypted_payload": {"ciphertext_b64": "abc"},
            "encryption_header": {"nonce_b64": "xyz"},
            "plaintext_metadata": {"label": "Personal"},
            "plaintext_payload": {"username": "alice"},
        }
    )

    assert "Personal" in text
    assert "Username: alice" in text


def test_format_note_detail_includes_decryption_error_when_unavailable() -> None:
    text = format_note_detail(
        {
            "note_id": "note_001",
            "note_type": "note",
            "state": "active",
            "encrypted_payload": {"ciphertext_b64": "abc"},
            "encryption_header": {"nonce_b64": "xyz"},
            "decryption_error": "Session vault key is not unlocked.",
        }
    )

    assert "Unlock vault to view decrypted content." in text
    assert "Session vault key is not unlocked." in text
