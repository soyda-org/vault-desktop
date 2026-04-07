from __future__ import annotations

import json
import re

from PySide6.QtGui import QTextDocument
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QPlainTextEdit,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
)


_MARKDOWN_PATTERN = re.compile(
    r"(^#{1,6}\s)|(^[-*+]\s)|(^\d+\.\s)|(```)|(`[^`]+`)|(\[[^\]]+\]\([^)]+\))|(\*\*[^*]+\*\*)|(^>\s)",
    re.MULTILINE,
)


def _looks_like_markdown(text: str) -> bool:
    return bool(_MARKDOWN_PATTERN.search(text or ""))


def _markdown_preview_stylesheet() -> str:
    return """
        body {
            color: #e2e8f0;
        }
        pre {
            background-color: #0b1220;
            border: 1px solid #243247;
            border-radius: 10px;
            padding: 12px;
            color: #e2e8f0;
            white-space: pre-wrap;
            font-family: "Courier New";
        }
        code {
            background-color: #111c2e;
            border: 1px solid #243247;
            border-radius: 6px;
            padding: 2px 4px;
            color: #dbeafe;
            font-family: "Courier New";
        }
    """


def _render_markdown_preview_html(text: str) -> str:
    document = QTextDocument()
    document.setMarkdown(text or "")
    html = document.toHtml()
    style_block = f"<style>{_markdown_preview_stylesheet()}</style>"
    if "<head>" in html:
        return html.replace("<head>", f"<head>{style_block}", 1)
    return f"{style_block}{html}"


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


class CredentialItemEditorDialog(QDialog):
    def __init__(
        self,
        *,
        title: str,
        summary: str,
        action_text: str,
        metadata_text: str,
        payload_text: str,
        reset_callback=None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(560, 310)

        self._extra_metadata: dict = {}
        self._extra_payload: dict = {}
        self._secret_key = "secret"
        self._url_key = "url"
        self._username_key = "username"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        self.label_input = QLineEdit()
        form.addRow("Label", self.label_input)

        self.username_input = QLineEdit()
        form.addRow("Username", self.username_input)

        self.secret_input = QLineEdit()
        self.secret_input.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Secret", self.secret_input)

        self.url_input = QLineEdit()
        form.addRow("URL", self.url_input)

        layout.addLayout(form)

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
        metadata_text: str,
        payload_text: str,
    ) -> None:
        metadata = self._parse_json_object(metadata_text)
        payload = self._parse_json_object(payload_text)

        label_value = ""
        candidate = metadata.get("label")
        if isinstance(candidate, str):
            label_value = candidate
        self._extra_metadata = {
            key: value for key, value in metadata.items() if key != "label"
        }

        username_value = ""
        self._username_key = "username"
        for key in ("username", "login", "email", "account"):
            candidate = payload.get(key)
            if isinstance(candidate, str):
                username_value = candidate
                self._username_key = key
                break

        secret_value = ""
        self._secret_key = "secret"
        for key in ("secret", "password", "token", "api_key"):
            candidate = payload.get(key)
            if isinstance(candidate, str):
                secret_value = candidate
                self._secret_key = key
                break

        url_value = ""
        self._url_key = "url"
        for key in ("url", "site", "uri"):
            candidate = payload.get(key)
            if isinstance(candidate, str):
                url_value = candidate
                self._url_key = key
                break

        self._extra_payload = {
            key: value
            for key, value in payload.items()
            if key not in {
                "username",
                "login",
                "email",
                "account",
                "secret",
                "password",
                "token",
                "api_key",
                "url",
                "site",
                "uri",
            }
        }

        self.label_input.setText(label_value)
        self.username_input.setText(username_value)
        self.secret_input.setText(secret_value)
        self.url_input.setText(url_value)

    def _reset_from_callback(self, reset_callback) -> None:
        metadata_text, payload_text = reset_callback()
        self._apply_json_defaults(
            metadata_text=metadata_text,
            payload_text=payload_text,
        )

    def metadata_text(self) -> str:
        metadata = dict(self._extra_metadata)
        label = self.label_input.text().strip()
        if label:
            metadata["label"] = label
        return json.dumps(metadata, indent=2)

    def payload_text(self) -> str:
        payload = dict(self._extra_payload)
        username = self.username_input.text().strip()
        secret = self.secret_input.text()
        url = self.url_input.text().strip()
        if username:
            payload[self._username_key] = username
        if secret:
            payload[self._secret_key] = secret
        if url:
            payload[self._url_key] = url
        return json.dumps(payload, indent=2)


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
        form.addRow("Title", self.title_input)

        self.tags_input = QLineEdit()
        form.addRow("Tags", self.tags_input)
        layout.addLayout(form)

        content_label = QLabel("Content")
        content_label.setObjectName("fieldLabel")
        layout.addWidget(content_label)

        self.content_stack = QStackedWidget()
        self.content_input = QPlainTextEdit()
        self.content_input.setMinimumHeight(260)
        self.content_preview = QTextEdit()
        self.content_preview.setReadOnly(True)
        self.content_preview.setMinimumHeight(260)
        self.content_preview.document().setDefaultStyleSheet(
            _markdown_preview_stylesheet()
        )
        self.content_stack.addWidget(self.content_input)
        self.content_stack.addWidget(self.content_preview)
        layout.addWidget(self.content_stack, 1)
        self._content_preview_enabled = False

        actions = QHBoxLayout()
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(8)

        if reset_callback is not None:
            self.reset_button = QPushButton("Reset Draft")
            self.reset_button.clicked.connect(lambda: self._reset_from_callback(reset_callback))
            actions.addWidget(self.reset_button)
        else:
            self.reset_button = None

        self.preview_button = QPushButton("Preview")
        self.preview_button.setProperty("tone", "secondary")
        self.preview_button.clicked.connect(self.toggle_preview_mode)
        actions.addWidget(self.preview_button)

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

    def _refresh_preview_content(self) -> None:
        content = self.content_input.toPlainText()
        if _looks_like_markdown(content):
            self.content_preview.setHtml(_render_markdown_preview_html(content))
        else:
            self.content_preview.setPlainText(content)

    def toggle_preview_mode(self) -> None:
        self._content_preview_enabled = not self._content_preview_enabled
        if self._content_preview_enabled:
            self._refresh_preview_content()
            self.content_stack.setCurrentWidget(self.content_preview)
            self.preview_button.setText("Edit")
            return

        self.content_stack.setCurrentWidget(self.content_input)
        self.preview_button.setText("Preview")

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
        if self._content_preview_enabled:
            self.toggle_preview_mode()

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
