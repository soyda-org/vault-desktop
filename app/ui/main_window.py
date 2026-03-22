from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.config import DesktopSettings
from app.services.api_client import ObjectDetailResult, ObjectListResult
from app.services.desktop_service import VaultDesktopService
from app.services.api_client import VaultApiClient
from app.ui.dashboard_formatters import (
    credential_list_label,
    file_list_label,
    format_credential_detail,
    format_credentials_items,
    format_file_detail,
    format_files_items,
    format_note_detail,
    format_notes_items,
    note_list_label,
)


class MainWindow(QMainWindow):
    def __init__(self, settings: DesktopSettings) -> None:
        super().__init__()
        self.settings = settings
        self.desktop_service = VaultDesktopService(
            api_client=VaultApiClient(settings.api_base_url)
        )

        self.setWindowTitle(settings.app_name)
        self.resize(1180, 780)

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

        self.load_credential_detail_button = QPushButton("Load Selected Credential")
        self.load_credential_detail_button.clicked.connect(self.load_credential_detail)

        self.load_note_detail_button = QPushButton("Load Selected Note")
        self.load_note_detail_button.clicked.connect(self.load_note_detail)

        self.load_file_detail_button = QPushButton("Load Selected File")
        self.load_file_detail_button.clicked.connect(self.load_file_detail)

        self.credentials_list = QListWidget()
        self.credentials_list.itemDoubleClicked.connect(lambda _: self.load_credential_detail())

        self.notes_list = QListWidget()
        self.notes_list.itemDoubleClicked.connect(lambda _: self.load_note_detail())

        self.files_list = QListWidget()
        self.files_list.itemDoubleClicked.connect(lambda _: self.load_file_detail())

        self.credentials_output = QTextEdit()
        self.credentials_output.setReadOnly(True)
        self.credentials_output.setPlaceholderText("Credential details will appear here.")

        self.notes_output = QTextEdit()
        self.notes_output.setReadOnly(True)
        self.notes_output.setPlaceholderText("Note details will appear here.")

        self.files_output = QTextEdit()
        self.files_output.setReadOnly(True)
        self.files_output.setPlaceholderText("File details will appear here.")

        self.tabs = QTabWidget()
        self.tabs.addTab(
            self._build_tab(
                self.credentials_list,
                self.load_credential_detail_button,
                self.credentials_output,
            ),
            "Credentials",
        )
        self.tabs.addTab(
            self._build_tab(
                self.notes_list,
                self.load_note_detail_button,
                self.notes_output,
            ),
            "Notes",
        )
        self.tabs.addTab(
            self._build_tab(
                self.files_list,
                self.load_file_detail_button,
                self.files_output,
            ),
            "Files",
        )

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

    def _build_tab(
        self,
        object_list: QListWidget,
        detail_button: QPushButton,
        output: QTextEdit,
    ) -> QWidget:
        left_layout = QVBoxLayout()
        left_layout.addWidget(detail_button)
        left_layout.addWidget(object_list)

        left_widget = QWidget()
        left_widget.setLayout(left_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_widget)
        splitter.addWidget(output)
        splitter.setSizes([360, 700])

        layout = QVBoxLayout()
        layout.addWidget(splitter)

        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def run_probe(self) -> None:
        result = self.desktop_service.probe()

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
        result = self.desktop_service.login(
            identifier=self.identifier_input.text().strip(),
            password=self.password_input.text(),
            device_name=self.device_name_input.text().strip(),
            platform=self.platform_input.text().strip(),
        )

        if result.error:
            self.status_label.setText(
                "Login failed.\n"
                f"Error: {result.error}"
            )
            return

        session = self.desktop_service.current_session()
        assert session is not None

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
        self.desktop_service.logout()
        self.status_label.setText("Session cleared locally.")
        self.credentials_list.clear()
        self.notes_list.clear()
        self.files_list.clear()
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
        result = self.desktop_service.fetch_credentials()
        self._render_credentials(result)

    def load_notes(self) -> None:
        result = self.desktop_service.fetch_notes()
        self._render_notes(result)

    def load_files(self) -> None:
        result = self.desktop_service.fetch_files()
        self._render_files(result)

    def load_all(self) -> None:
        credentials_result = self.desktop_service.fetch_credentials()
        notes_result = self.desktop_service.fetch_notes()
        files_result = self.desktop_service.fetch_files()

        self._render_credentials(credentials_result)
        self._render_notes(notes_result)
        self._render_files(files_result)

        self.status_label.setText("Dashboard refresh completed.")

    def load_credential_detail(self) -> None:
        item = self.credentials_list.currentItem()
        if item is None:
            self.status_label.setText("Select a credential first.")
            return

        credential_id = item.data(Qt.ItemDataRole.UserRole)
        result = self.desktop_service.fetch_credential_detail(credential_id)
        self._render_credential_detail(result)

    def load_note_detail(self) -> None:
        item = self.notes_list.currentItem()
        if item is None:
            self.status_label.setText("Select a note first.")
            return

        note_id = item.data(Qt.ItemDataRole.UserRole)
        result = self.desktop_service.fetch_note_detail(note_id)
        self._render_note_detail(result)

    def load_file_detail(self) -> None:
        item = self.files_list.currentItem()
        if item is None:
            self.status_label.setText("Select a file first.")
            return

        file_id = item.data(Qt.ItemDataRole.UserRole)
        result = self.desktop_service.fetch_file_detail(file_id)
        self._render_file_detail(result)

    def _render_credentials(self, result: ObjectListResult) -> None:
        if result.error:
            self.credentials_output.setPlainText(
                f"Credentials fetch failed.\nError: {result.error}"
            )
            return

        self.credentials_list.clear()
        for entry in result.items:
            widget_item = QListWidgetItem(credential_list_label(entry))
            widget_item.setData(Qt.ItemDataRole.UserRole, entry.get("credential_id"))
            self.credentials_list.addItem(widget_item)

        self.credentials_output.setPlainText(format_credentials_items(result.items))

        if self.credentials_list.count() > 0:
            self.credentials_list.setCurrentRow(0)

    def _render_notes(self, result: ObjectListResult) -> None:
        if result.error:
            self.notes_output.setPlainText(
                f"Notes fetch failed.\nError: {result.error}"
            )
            return

        self.notes_list.clear()
        for entry in result.items:
            widget_item = QListWidgetItem(note_list_label(entry))
            widget_item.setData(Qt.ItemDataRole.UserRole, entry.get("note_id"))
            self.notes_list.addItem(widget_item)

        self.notes_output.setPlainText(format_notes_items(result.items))

        if self.notes_list.count() > 0:
            self.notes_list.setCurrentRow(0)

    def _render_files(self, result: ObjectListResult) -> None:
        if result.error:
            self.files_output.setPlainText(
                f"Files fetch failed.\nError: {result.error}"
            )
            return

        self.files_list.clear()
        for entry in result.items:
            widget_item = QListWidgetItem(file_list_label(entry))
            widget_item.setData(Qt.ItemDataRole.UserRole, entry.get("file_id"))
            self.files_list.addItem(widget_item)

        self.files_output.setPlainText(format_files_items(result.items))

        if self.files_list.count() > 0:
            self.files_list.setCurrentRow(0)

    def _render_credential_detail(self, result: ObjectDetailResult) -> None:
        if result.error:
            self.credentials_output.setPlainText(
                f"Credential detail fetch failed.\nError: {result.error}"
            )
            return

        item = result.item or {}
        self.credentials_output.setPlainText(format_credential_detail(item))

    def _render_note_detail(self, result: ObjectDetailResult) -> None:
        if result.error:
            self.notes_output.setPlainText(
                f"Note detail fetch failed.\nError: {result.error}"
            )
            return

        item = result.item or {}
        self.notes_output.setPlainText(format_note_detail(item))

    def _render_file_detail(self, result: ObjectDetailResult) -> None:
        if result.error:
            self.files_output.setPlainText(
                f"File detail fetch failed.\nError: {result.error}"
            )
            return

        item = result.item or {}
        self.files_output.setPlainText(format_file_detail(item))

    def refresh_session_label(self) -> None:
        if not self.desktop_service.is_authenticated():
            self.session_label.setText("No active session.")
            return

        session = self.desktop_service.current_session()
        assert session is not None

        self.session_label.setText(
            "Active session.\n"
            f"Identifier: {session.identifier}\n"
            f"User ID: {session.user_id}\n"
            f"Device ID: {session.device_id}\n"
            f"Session ID: {session.session_id}"
        )
