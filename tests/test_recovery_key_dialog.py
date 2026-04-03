from __future__ import annotations

import os
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from app.ui.recovery_key_dialog import RecoveryKeyDialog

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture
def app_fixture() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_continue_requires_saved_ack(app_fixture) -> None:
    dialog = RecoveryKeyDialog("cmVjb3Y=")

    assert dialog.continue_button.isEnabled() is False

    dialog.saved_checkbox.setChecked(True)

    assert dialog.continue_button.isEnabled() is True


def test_copy_updates_feedback_and_clipboard(app_fixture) -> None:
    dialog = RecoveryKeyDialog("cmVjb3Y=")

    dialog._copy_key()

    assert QApplication.clipboard().text() == "cmVjb3Y="
    assert dialog.feedback_label.text() == "Recovery key copied to clipboard."


def test_save_updates_feedback(monkeypatch, tmp_path: Path, app_fixture) -> None:
    target = tmp_path / "recovery-key.txt"
    monkeypatch.setattr(
        "app.ui.recovery_key_dialog.QFileDialog.getSaveFileName",
        lambda *args, **kwargs: (str(target), "Text files (*.txt)"),
    )

    dialog = RecoveryKeyDialog("cmVjb3Y=")
    dialog._save_key()

    assert target.read_text(encoding="utf-8") == "cmVjb3Y=\n"
    assert dialog.feedback_label.text() == f"Recovery key saved to: {target}"
