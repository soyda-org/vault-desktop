from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QPlainTextEdit,
    QVBoxLayout,
)


class JsonItemEditorDialog(QDialog):
    def __init__(
        self,
        *,
        title: str,
        summary: str,
        action_text: str,
        metadata_text: str,
        payload_text: str,
        header_text: str = "",
        note_type: str | None = None,
        reset_callback=None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 620)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        summary_label = QLabel(summary)
        summary_label.setObjectName("dialogSummary")
        summary_label.setWordWrap(True)
        layout.addWidget(summary_label)

        if note_type is not None:
            type_form = QFormLayout()
            type_form.setContentsMargins(0, 0, 0, 0)
            type_form.setHorizontalSpacing(10)
            type_form.setVerticalSpacing(8)
            self.note_type_input = QLineEdit(note_type)
            type_form.addRow("Note type", self.note_type_input)
            layout.addLayout(type_form)
        else:
            self.note_type_input = None

        metadata_label = QLabel("Metadata JSON")
        metadata_label.setObjectName("fieldLabel")
        layout.addWidget(metadata_label)

        self.metadata_input = QPlainTextEdit()
        self.metadata_input.setPlainText(metadata_text)
        self.metadata_input.setPlaceholderText("Optional JSON object for labels, tags, or metadata.")
        self.metadata_input.setMinimumHeight(110)
        layout.addWidget(self.metadata_input)

        payload_label = QLabel("Payload JSON")
        payload_label.setObjectName("fieldLabel")
        layout.addWidget(payload_label)

        self.payload_input = QPlainTextEdit()
        self.payload_input.setPlainText(payload_text)
        self.payload_input.setPlaceholderText("Required JSON object for the encrypted payload.")
        self.payload_input.setMinimumHeight(220)
        layout.addWidget(self.payload_input, 1)

        header_label = QLabel("Last generated header")
        header_label.setObjectName("fieldLabel")
        layout.addWidget(header_label)

        self.header_input = QPlainTextEdit()
        self.header_input.setReadOnly(True)
        self.header_input.setPlainText(header_text)
        self.header_input.setPlaceholderText("A generated encryption header will appear here after save.")
        self.header_input.setMinimumHeight(90)
        layout.addWidget(self.header_input)

        actions = QHBoxLayout()
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(8)

        if reset_callback is not None:
            self.reset_button = QPushButton("Reset Draft")
            self.reset_button.clicked.connect(lambda: self._reset_from_callback(reset_callback))
            actions.addWidget(self.reset_button)
        else:
            self.reset_button = None

        actions.addStretch(1)

        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.save_button = self.button_box.addButton(action_text, QDialogButtonBox.ButtonRole.AcceptRole)
        self.save_button.setProperty("tone", "primary")
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        actions.addWidget(self.button_box)
        layout.addLayout(actions)

    def _reset_from_callback(self, reset_callback) -> None:
        metadata_text, payload_text, note_type = reset_callback()
        self.metadata_input.setPlainText(metadata_text)
        self.payload_input.setPlainText(payload_text)
        self.header_input.clear()
        if self.note_type_input is not None and note_type is not None:
            self.note_type_input.setText(note_type)

    def metadata_text(self) -> str:
        return self.metadata_input.toPlainText()

    def payload_text(self) -> str:
        return self.payload_input.toPlainText()

    def note_type_text(self) -> str | None:
        if self.note_type_input is None:
            return None
        return self.note_type_input.text()

