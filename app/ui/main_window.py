from __future__ import annotations

from PySide6.QtWidgets import (
    QApplication,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.config import DesktopSettings
from app.core.session import DesktopSession, SessionStore
from app.services.api_client import LoginPayload, ObjectListResult, VaultApiClient
from app.ui.dashboard_formatters import (
    format_credentials_items,
    format_files_items,
    format_notes_items,
)


class MainWindow(QMainWindow):
    def __init__(self, settings: DesktopSettings) -> None:
        super().__init__()
        self.settings = settings
        self.api_client = VaultApiClient(settings.api_base_url)
        self.session_store = SessionStore()

        self.setWindowTitle(settings.app_name)
        self.resize(980, 720)

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

        self.close_button = QPushButton("Close App")
        self.close_button.clicked.connect(self.run_close)

        self.load_credentials_button = QPushButton("Load Credentials")
        self.load_credentials_button.clicked.connect(self.load_credentials)

        self.load_notes_button = QPushButton("Load Notes")
        self.load_notes_button.clicked.connect(self.load_notes)

        self.load_files_button = QPushButton("Load Files")
        self.load_files_button.clicked.connect(self.load_files)

        self.load_all_button = QPushButton("Load All")
        self.load_all_button.clicked.connect(self.load_all)

        self.credentials_output = QTextEdit()
        self.credentials_output.setReadOnly(True)
        self.credentials_output.setPlaceholderText("Credentials output will appear here.")

        self.notes_output = QTextEdit()
        self.notes_output.setReadOnly(True)
        self.notes_output.setPlaceholderText("Notes output will appear here.")

        self.files_output = QTextEdit()
        self.files_output.setReadOnly(True)
        self.files_output.setPlaceholderText("Files output will appear here.")

        self.tabs = QTabWidget()
        self.tabs.addTab(self.credentials_output, "Credentials")
        self.tabs.addTab(self.notes_output, "Notes")
        self.tabs.addTab(self.files_output, "Files")

        form_layout = QFormLayout()
        form_layout.addRow("Identifier", self.identifier_input)
        form_layout.addRow("Password", self.password_input)
        form_layout.addRow("Device name", self.device_name_input)
        form_layout.addRow("Platform", self.platform_input)

        auth_buttons_layout = QHBoxLayout()
        auth_buttons_layout.addWidget(self.login_button)
        auth_buttons_layout.addWidget(self.logout_button)
        auth_buttons_layout.addWidget(self.close_button)

        dashboard_buttons_layout = QHBoxLayout()
        dashboard_buttons_layout.addWidget(self.load_credentials_button)
        dashboard_buttons_layout.addWidget(self.load_notes_button)
        dashboard_buttons_layout.addWidget(self.load_files_button)
        dashboard_buttons_layout.addWidget(self.load_all_button)

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"App: {settings.app_name}"))
        layout.addWidget(QLabel(f"Environment: {settings.environment}"))
        layout.addWidget(QLabel(f"API base URL: {settings.api_base_url}"))
        layout.addWidget(self.probe_button)
        layout.addLayout(form_layout)
        layout.addLayout(auth_buttons_layout)
        layout.addWidget(self.status_label)
        layout.addWidget(self.session_label)
        layout.addWidget(QLabel("Dashboard"))
        layout.addLayout(dashboard_buttons_layout)
        layout.addWidget(self.tabs)

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
        self.credentials_output.clear()
        self.notes_output.clear()
        self.files_output.clear()
        self.refresh_session_label()

    def run_close(self) -> None:
        app = QApplication.instance()
        if app is not None:
            app.quit()
        else:
            self.close()

    def load_credentials(self) -> None:
        session = self._require_session()
        if session is None:
            return

        result = self.api_client.fetch_credentials(
            identifier=session.identifier,
            access_token=session.access_token,
        )
        self._render_credentials(result)

    def load_notes(self) -> None:
        session = self._require_session()
        if session is None:
            return

        result = self.api_client.fetch_notes(
            identifier=session.identifier,
            access_token=session.access_token,
        )
        self._render_notes(result)

    def load_files(self) -> None:
        session = self._require_session()
        if session is None:
            return

        result = self.api_client.fetch_files(
            identifier=session.identifier,
            access_token=session.access_token,
        )
        self._render_files(result)

    def load_all(self) -> None:
        session = self._require_session()
        if session is None:
            return

        credentials_result = self.api_client.fetch_credentials(
            identifier=session.identifier,
            access_token=session.access_token,
        )
        notes_result = self.api_client.fetch_notes(
            identifier=session.identifier,
            access_token=session.access_token,
        )
        files_result = self.api_client.fetch_files(
            identifier=session.identifier,
            access_token=session.access_token,
        )

        self._render_credentials(credentials_result)
        self._render_notes(notes_result)
        self._render_files(files_result)

        self.status_label.setText("Dashboard refresh completed.")

    def _require_session(self) -> DesktopSession | None:
        session = self.session_store.current
        if session is None:
            self.status_label.setText("No active session. Login first.")
            return None
        return session

    def _render_credentials(self, result: ObjectListResult) -> None:
        if result.error:
            self.credentials_output.setPlainText(
                f"Credentials fetch failed.\nError: {result.error}"
            )
            return

        self.credentials_output.setPlainText(format_credentials_items(result.items))

    def _render_notes(self, result: ObjectListResult) -> None:
        if result.error:
            self.notes_output.setPlainText(
                f"Notes fetch failed.\nError: {result.error}"
            )
            return

        self.notes_output.setPlainText(format_notes_items(result.items))

    def _render_files(self, result: ObjectListResult) -> None:
        if result.error:
            self.files_output.setPlainText(
                f"Files fetch failed.\nError: {result.error}"
            )
            return

        self.files_output.setPlainText(format_files_items(result.items))

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
