from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)


class RecoveryKeyDialog(QDialog):
    def __init__(self, recovery_key_b64: str, parent=None) -> None:
        super().__init__(parent)
        self.recovery_key_b64 = recovery_key_b64
        self.setWindowTitle("Save Recovery Key")
        self.setModal(True)
        self.setWindowFlag(Qt.WindowCloseButtonHint, False)

        layout = QVBoxLayout(self)

        warning = QLabel(
            "This recovery key will only be shown once.\n"
            "Save it now. It will not be accessible again from the app."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)

        self.feedback_label = QLabel("Save or copy the key, then confirm you stored it safely.")
        self.feedback_label.setWordWrap(True)
        layout.addWidget(self.feedback_label)

        self.key_view = QPlainTextEdit()
        self.key_view.setReadOnly(True)
        self.key_view.setPlainText(recovery_key_b64)
        layout.addWidget(self.key_view)

        button_row = QHBoxLayout()
        self.copy_button = QPushButton("Copy")
        self.copy_button.clicked.connect(self._copy_key)
        button_row.addWidget(self.copy_button)

        self.save_button = QPushButton("Save as TXT")
        self.save_button.clicked.connect(self._save_key)
        button_row.addWidget(self.save_button)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        self.saved_checkbox = QCheckBox("I saved this recovery key somewhere safe.")
        self.saved_checkbox.toggled.connect(self._refresh_continue_state)
        layout.addWidget(self.saved_checkbox)

        self.continue_button = QPushButton("Continue")
        self.continue_button.setEnabled(False)
        self.continue_button.clicked.connect(self.accept)
        layout.addWidget(self.continue_button)

    def _refresh_continue_state(self) -> None:
        self.continue_button.setEnabled(self.saved_checkbox.isChecked())

    def _copy_key(self) -> None:
        QApplication.clipboard().setText(self.recovery_key_b64)
        self.feedback_label.setText("Recovery key copied to clipboard.")

    def _save_key(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Recovery Key",
            "recovery-key.txt",
            "Text files (*.txt)",
        )
        if not filename:
            return
        Path(filename).write_text(self.recovery_key_b64 + "\n", encoding="utf-8")
        self.feedback_label.setText(f"Recovery key saved to: {filename}")


def show_recovery_key_dialog(parent, recovery_key_b64: str) -> bool:
    dialog = RecoveryKeyDialog(recovery_key_b64=recovery_key_b64, parent=parent)
    return dialog.exec() == QDialog.DialogCode.Accepted
