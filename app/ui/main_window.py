from __future__ import annotations

import json

from PySide6.QtWidgets import (
    QFormLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.config import DesktopSettings
from app.core.session import DesktopSession, SessionStore
from app.services.api_client import LoginPayload, ObjectListResult, VaultApiClient


class MainWindow(QMainWindow):
    def __init__(self, settings: DesktopSettings) -> None:
        super().__init__()
        self.settings = settings
        self.api_client = VaultApiClient(settings.api_base_url)
        self.session_store = SessionStore()

        self.setWindowTitle(settings.app_name)
        self.resize(860, 620)

        self.status_label = QLabel("Press 'Probe API' or login.")
        self.status_label.setWordWrap(True)

        self.session_label = QLabel("No active session.")
        self.session_label.setWordWrap(True)

        self.identifier_input = QLineEdit()
        self.identifier_input.setText("alice")

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setText("strong-password")

        self.device_name_input = QLineEdit()
        self.device_name_input.setText("vault-desktop-dev")

        self.platform_input = QLineEdit()
        self.platform_input.setText("linux")

        self.probe_button = QPushButton("Probe API")
        self.probe_button.clicked.connect(self.run_probe)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.run_login)

        self.logout_button = QPushButton("Logout")
        self.logout_button.clicked.connect(self.run_logout)

        self.load_credentials_button = QPushButton("Load Credentials")
        self.load_credentials_button.clicked.connect(self.load_credentials)

        self.load_notes_button = QPushButton("Load Notes")
        self.load_notes_button.clicked.connect(self.load_notes)

        self.load_files_button = QPushButton("Load Files")
        self.load_files_button.clicked.connect(self.load_files)

        self.dashboard_output = QTextEdit()
        self.dashboard_output.setReadOnly(True)
        self.dashboard_output.setPlaceholderText("Dashboard output will appear here.")

        form_layout = QFormLayout()
        form_layout.addRow("Identifier", self.identifier_input)
        form_layout.addRow("Password", self.password_input)
        form_layout.addRow("Device name", self.device_name_input)
        form_layout.addRow("Platform", self.platform_input)

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"App: {settings.app_name}"))
        layout.addWidget(QLabel(f"Environment: {settings.environment}"))
        layout.addWidget(QLabel(f"API base URL: {settings.api_base_url}"))
        layout.addWidget(self.probe_button)
        layout.addLayout(form_layout)
        layout.addWidget(self.login_button)
        layout.addWidget(self.logout_button)
        layout.addWidget(self.load_credentials_button)
        layout.addWidget(self.load_notes_button)
        layout.addWidget(self.load_files_button)
        layout.addWidget(self.status_label)
        layout.addWidget(self.session_label)
        layout.addWidget(QLabel("Dashboard data"))
        layout.addWidget(self.dashboard_output)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.refresh_session_label()

    def run_probe(self) -> None:
        result = self.api_client.probe()

        if result.error:
            self.status_label.setText(
                "Backend probe failed.\n"
                f"Error: {result.error}"
            )
            return

        self.status_label.setText(
            "Backend probe succeeded.\n"
            f"Health OK: {result.health_ok}\n"
            f"Project: {result.project_name}\n"
            f"Version: {result.version}\n"
            f"Environment: {result.environment}"
        )

    def run_login(self) -> None:
        payload = LoginPayload(
            identifier=self.identifier_input.text().strip(),
            password=self.password_input.text(),
            device_name=self.device_name_input.text().strip(),
            platform=self.platform_input.text().strip(),
        )
        result = self.api_client.login(payload)

        if result.error:
            self.status_label.setText(
                "Login failed.\n"
                f"Error: {result.error}"
            )
            return

        session = DesktopSession(
            identifier=payload.identifier,
            user_id=result.user_id or "",
            device_id=result.device_id or "",
            session_id=result.session_id or "",
            access_token=result.access_token or "",
            refresh_token=result.refresh_token or "",
            token_type=result.token_type or "",
        )
        self.session_store.set_session(session)

        access_preview = (
            session.access_token[:24] + "..."
            if len(session.access_token) > 24
            else session.access_token
        )

        self.status_label.setText(
            "Login succeeded.\n"
            f"User ID: {session.user_id}\n"
            f"Device ID: {session.device_id}\n"
            f"Session ID: {session.session_id}\n"
            f"Token type: {session.token_type}\n"
            f"Access token preview: {access_preview}"
        )
        self.refresh_session_label()

    def run_logout(self) -> None:
        self.session_store.clear()
        self.status_label.setText("Session cleared locally.")
        self.dashboard_output.clear()
        self.refresh_session_label()

    def load_credentials(self) -> None:
        session = self._require_session()
        if session is None:
            return

        result = self.api_client.fetch_credentials(
            identifier=session.identifier,
            access_token=session.access_token,
        )
        self._render_object_list("Credentials", result)

    def load_notes(self) -> None:
        session = self._require_session()
        if session is None:
            return

        result = self.api_client.fetch_notes(
            identifier=session.identifier,
            access_token=session.access_token,
        )
        self._render_object_list("Notes", result)

    def load_files(self) -> None:
        session = self._require_session()
        if session is None:
            return

        result = self.api_client.fetch_files(
            identifier=session.identifier,
            access_token=session.access_token,
        )
        self._render_object_list("Files", result)

    def _require_session(self) -> DesktopSession | None:
        session = self.session_store.current
        if session is None:
            self.status_label.setText("No active session. Login first.")
            return None
        return session

    def _render_object_list(self, title: str, result: ObjectListResult) -> None:
        if result.error:
            self.dashboard_output.setPlainText(
                f"{title} fetch failed.\nError: {result.error}"
            )
            return

        pretty_items = json.dumps(result.items, indent=2)
        self.dashboard_output.setPlainText(
            f"{title} loaded successfully.\n"
            f"Count: {len(result.items)}\n\n"
            f"{pretty_items}"
        )

    def refresh_session_label(self) -> None:
        if not self.session_store.is_authenticated():
            self.session_label.setText("No active session.")
            return

        session = self.session_store.current
        assert session is not None

        self.session_label.setText(
            "Active session.\n"
            f"Identifier: {session.identifier}\n"
            f"User ID: {session.user_id}\n"
            f"Device ID: {session.device_id}\n"
            f"Session ID: {session.session_id}"
        )
