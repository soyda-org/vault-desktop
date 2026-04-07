from __future__ import annotations

import json
import os

import pytest
from PySide6.QtWidgets import QApplication

from app.ui.item_editor_dialog import NoteItemEditorDialog

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
    assert dialog.header_input.toPlainText() == ""


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
