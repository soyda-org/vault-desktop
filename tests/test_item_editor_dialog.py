from __future__ import annotations

import json
import os
import string

import pytest
from PySide6.QtWidgets import QApplication

from app.ui.item_editor_dialog import CredentialItemEditorDialog, NoteItemEditorDialog


def test_credential_item_editor_dialog_prefills_and_emits_json(app_fixture) -> None:
    dialog = CredentialItemEditorDialog(
        title="Edit Credential",
        summary="Edit credential",
        action_text="Save Credential",
        metadata_text=json.dumps(
            {"label": "Personal", "color": "blue"},
            indent=2,
        ),
        payload_text=json.dumps(
            {
                "username": "alice",
                "secret": "s3cr3t",
                "url": "https://example.com",
                "pinned": True,
            },
            indent=2,
        ),
    )

    assert dialog.label_input.text() == "Personal"
    assert dialog.username_input.text() == "alice"
    assert dialog.secret_input.text() == "s3cr3t"
    assert dialog.url_input.text() == "https://example.com"

    dialog.label_input.setText("Work")
    dialog.username_input.setText("bob")
    dialog.secret_input.setText("n3wsecret")
    dialog.url_input.setText("https://corp.example.com")

    assert json.loads(dialog.metadata_text()) == {
        "label": "Work",
        "color": "blue",
    }
    assert json.loads(dialog.payload_text()) == {
        "username": "bob",
        "secret": "n3wsecret",
        "url": "https://corp.example.com",
        "pinned": True,
    }


def test_credential_item_editor_dialog_reset_restores_friendly_fields(app_fixture) -> None:
    dialog = CredentialItemEditorDialog(
        title="New Credential",
        summary="Create credential",
        action_text="Create Credential",
        metadata_text="{}",
        payload_text="{}",
        reset_callback=lambda: (
            json.dumps({"label": "Personal"}, indent=2),
            json.dumps(
                {
                    "username": "alice",
                    "secret": "s3cr3t",
                    "url": "https://example.com",
                },
                indent=2,
            ),
        ),
    )

    dialog.label_input.setText("Temp")
    dialog.username_input.setText("tmp")
    dialog.secret_input.setText("throwaway")
    dialog.url_input.setText("https://tmp.example.com")

    dialog.reset_button.click()

    assert dialog.label_input.text() == "Personal"
    assert dialog.username_input.text() == "alice"
    assert dialog.secret_input.text() == "s3cr3t"
    assert dialog.url_input.text() == "https://example.com"


def test_credential_item_editor_dialog_empty_defaults_render_blank_fields(app_fixture) -> None:
    dialog = CredentialItemEditorDialog(
        title="New Credential",
        summary="Create credential",
        action_text="Create Credential",
        metadata_text="{}",
        payload_text="{}",
    )

    assert dialog.label_input.text() == ""
    assert dialog.username_input.text() == ""
    assert dialog.secret_input.text() == ""
    assert dialog.url_input.text() == ""


def test_credential_item_editor_dialog_secret_toggle_switches_visibility(app_fixture) -> None:
    dialog = CredentialItemEditorDialog(
        title="New Credential",
        summary="Create credential",
        action_text="Create Credential",
        metadata_text="{}",
        payload_text=json.dumps({"secret": "s3cr3t"}, indent=2),
    )

    assert dialog.secret_input.echoMode() == dialog.secret_input.EchoMode.Password
    assert dialog.toggle_secret_button.text() == "Show"

    dialog.toggle_secret_button.click()

    assert dialog.secret_input.echoMode() == dialog.secret_input.EchoMode.Normal
    assert dialog.toggle_secret_button.text() == "Hide"

    dialog.toggle_secret_button.click()

    assert dialog.secret_input.echoMode() == dialog.secret_input.EchoMode.Password
    assert dialog.toggle_secret_button.text() == "Show"


def test_credential_item_editor_dialog_generate_sets_strong_password(app_fixture) -> None:
    dialog = CredentialItemEditorDialog(
        title="New Credential",
        summary="Create credential",
        action_text="Create Credential",
        metadata_text="{}",
        payload_text="{}",
    )

    dialog.generate_secret_button.click()

    generated = dialog.secret_input.text()
    assert len(generated) == 32
    assert any(char in string.ascii_uppercase for char in generated)
    assert any(char in string.ascii_lowercase for char in generated)
    assert any(char in string.digits for char in generated)
    assert any(char in "!@#$%^&*()-_=+[]{};:,.?/" for char in generated)
    assert dialog.secret_input.echoMode() == dialog.secret_input.EchoMode.Normal
    assert dialog.toggle_secret_button.text() == "Hide"

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture
def app_fixture() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_note_item_editor_dialog_prefills_and_emits_json(app_fixture) -> None:
    dialog = NoteItemEditorDialog(
        title="Edit Note",
        summary="Edit note",
        action_text="Save Note",
        note_type="note",
        metadata_text=json.dumps(
            {"tags": ["todo", "personal"], "color": "blue"},
            indent=2,
        ),
        payload_text=json.dumps(
            {
                "title": "Daily plan",
                "body": "Buy milk",
                "pinned": True,
            },
            indent=2,
        ),
    )

    assert dialog.note_type_text() == "note"
    assert dialog.title_input.text() == "Daily plan"
    assert dialog.tags_input.text() == "todo, personal"
    assert dialog.content_input.toPlainText() == "Buy milk"

    dialog.title_input.setText("Updated title")
    dialog.tags_input.setText("todo, work")
    dialog.content_input.setPlainText("Ship patch")

    assert json.loads(dialog.metadata_text()) == {
        "tags": ["todo", "work"],
        "color": "blue",
    }
    assert json.loads(dialog.payload_text()) == {
        "title": "Updated title",
        "body": "Ship patch",
        "pinned": True,
    }


def test_note_item_editor_dialog_reset_callback_restores_friendly_fields(
    app_fixture,
) -> None:
    dialog = NoteItemEditorDialog(
        title="New Note",
        summary="Create note",
        action_text="Create Note",
        note_type="note",
        metadata_text="{}",
        payload_text="{}",
        reset_callback=lambda: (
            "journal",
            json.dumps({"tags": ["ideas"]}, indent=2),
            json.dumps({"title": "Thought", "content": "Draft body"}, indent=2),
        ),
    )

    dialog.note_type_input.setText("scratch")
    dialog.title_input.setText("Temp")
    dialog.tags_input.setText("tmp")
    dialog.content_input.setPlainText("Throwaway")

    dialog.reset_button.click()

    assert dialog.note_type_text() == "journal"
    assert dialog.title_input.text() == "Thought"
    assert dialog.tags_input.text() == "ideas"
    assert dialog.content_input.toPlainText() == "Draft body"


def test_note_item_editor_dialog_has_no_placeholders_or_header_preview(app_fixture) -> None:
    dialog = NoteItemEditorDialog(
        title="New Note",
        summary="Create note",
        action_text="Create Note",
        note_type="note",
        metadata_text="{}",
        payload_text="{}",
    )

    assert dialog.title_input.placeholderText() == ""
    assert dialog.tags_input.placeholderText() == ""
    assert dialog.content_input.placeholderText() == ""
    assert not hasattr(dialog, "header_input")


def test_note_item_editor_dialog_can_lock_note_type_in_edit_mode(app_fixture) -> None:
    dialog = NoteItemEditorDialog(
        title="Edit Note",
        summary="Edit note",
        action_text="Save Note",
        note_type="note",
        note_type_read_only=True,
        metadata_text=json.dumps({"tags": ["todo"]}, indent=2),
        payload_text=json.dumps({"title": "Daily plan", "content": "Buy milk"}, indent=2),
    )

    assert dialog.note_type_input.isReadOnly() is True
    assert dialog.note_type_text() == "note"


def test_note_item_editor_dialog_empty_defaults_render_blank_fields(app_fixture) -> None:
    dialog = NoteItemEditorDialog(
        title="New Note",
        summary="Create note",
        action_text="Create Note",
        note_type="note",
        metadata_text="{}",
        payload_text="{}",
    )

    assert dialog.note_type_text() == "note"
    assert dialog.title_input.text() == ""
    assert dialog.tags_input.text() == ""
    assert dialog.content_input.toPlainText() == ""


def test_note_item_editor_dialog_preview_toggles_markdown_render(app_fixture) -> None:
    dialog = NoteItemEditorDialog(
        title="New Note",
        summary="Create note",
        action_text="Create Note",
        note_type="note",
        metadata_text="{}",
        payload_text=json.dumps(
            {"content": "# Title\n\n- buy milk"},
            indent=2,
        ),
    )

    assert dialog.preview_button.text() == "Preview"
    assert dialog.content_stack.currentWidget() is dialog.content_input

    dialog.preview_button.click()

    assert dialog.preview_button.text() == "Edit"
    assert dialog.content_stack.currentWidget() is dialog.content_preview
    assert "Title" in dialog.content_preview.toPlainText()
    assert "buy milk" in dialog.content_preview.toPlainText()

    dialog.preview_button.click()

    assert dialog.preview_button.text() == "Preview"
    assert dialog.content_stack.currentWidget() is dialog.content_input
