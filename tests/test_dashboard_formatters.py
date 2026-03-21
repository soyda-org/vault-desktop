from app.ui.dashboard_formatters import (
    format_credentials_items,
    format_files_items,
    format_notes_items,
)


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
