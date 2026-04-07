from __future__ import annotations

import json

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


class NoteItemEditorDialog(QDialog):
    def __init__(
        self,
        *,
        title: str,
        summary: str,
        action_text: str,
        metadata_text: str,
        payload_text: str,
        header_text: str = "",
        note_type: str = "note",
        note_type_read_only: bool = False,
        reset_callback=None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 560)

        self._extra_metadata: dict = {}
        self._extra_payload: dict = {}
        self._content_key = "content"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        summary_label = QLabel(summary)
        summary_label.setObjectName("dialogSummary")
        summary_label.setWordWrap(True)
        layout.addWidget(summary_label)

        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        self.note_type_input = QLineEdit(note_type)
        self.note_type_input.setReadOnly(note_type_read_only)
        if note_type_read_only:
            self.note_type_input.setProperty("ghostField", True)
            self.note_type_input.setStyleSheet(
                "color: #94a3b8; background-color: rgba(148, 163, 184, 0.10);"
            )
        form.addRow("Note type", self.note_type_input)

        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("Short note title")
        form.addRow("Title", self.title_input)

        self.tags_input = QLineEdit()
        self.tags_input.setPlaceholderText("Comma-separated tags, for example: todo, personal")
        form.addRow("Tags", self.tags_input)
        layout.addLayout(form)

        content_label = QLabel("Content")
        content_label.setObjectName("fieldLabel")
        layout.addWidget(content_label)

        self.content_input = QPlainTextEdit()
        self.content_input.setPlaceholderText("Write the note body here.")
        self.content_input.setMinimumHeight(260)
        layout.addWidget(self.content_input, 1)

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

        self._apply_json_defaults(
            note_type=note_type,
            metadata_text=metadata_text,
            payload_text=payload_text,
        )

    def _parse_json_object(self, text: str) -> dict:
        raw = text.strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
        return {}

    def _apply_json_defaults(
        self,
        *,
        note_type: str,
        metadata_text: str,
        payload_text: str,
    ) -> None:
        metadata = self._parse_json_object(metadata_text)
        payload = self._parse_json_object(payload_text)

        tags = metadata.get("tags")
        if isinstance(tags, list):
            tag_values = [str(tag).strip() for tag in tags if str(tag).strip()]
        else:
            tag_values = []
        self._extra_metadata = {
            key: value for key, value in metadata.items() if key != "tags"
        }

        title_value = ""
        for key in ("title", "label", "name"):
            candidate = payload.get(key)
            if isinstance(candidate, str) and candidate.strip():
                title_value = candidate
                break

        content_value = ""
        self._content_key = "content"
        for key in ("content", "body", "text"):
            candidate = payload.get(key)
            if isinstance(candidate, str):
                content_value = candidate
                self._content_key = key
                break

        self._extra_payload = {
            key: value
            for key, value in payload.items()
            if key not in {"title", "content", "body", "text"}
        }

        self.note_type_input.setText(note_type or "note")
        self.title_input.setText(title_value)
        self.tags_input.setText(", ".join(tag_values))
        self.content_input.setPlainText(content_value)

    def _reset_from_callback(self, reset_callback) -> None:
        note_type, metadata_text, payload_text = reset_callback()
        self._apply_json_defaults(
            note_type=note_type or "note",
            metadata_text=metadata_text,
            payload_text=payload_text,
        )
        self.header_input.clear()

    def metadata_text(self) -> str:
        metadata = dict(self._extra_metadata)
        raw_tags = [tag.strip() for tag in self.tags_input.text().split(",")]
        tags = [tag for tag in raw_tags if tag]
        if tags:
            metadata["tags"] = tags
        return json.dumps(metadata, indent=2)

    def payload_text(self) -> str:
        payload = dict(self._extra_payload)
        title = self.title_input.text().strip()
        content = self.content_input.toPlainText()
        if title:
            payload["title"] = title
        payload[self._content_key] = content
        return json.dumps(payload, indent=2)

    def note_type_text(self) -> str:
        return self.note_type_input.text()
