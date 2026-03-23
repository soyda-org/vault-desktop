from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.config import DesktopSettings
from app.core.local_settings import LocalSettingsStore, PersistedUiSettings
from app.services.api_client import (
    ObjectCreateResult,
    ObjectDetailResult,
    ObjectListResult,
    VaultApiClient,
)
from app.services.desktop_service import VaultDesktopService
from app.services.file_crypto_bridge import (
    build_encrypted_file_finalize_payload,
    inspect_plaintext_file,
)
from app.services.password_generator import (
    PasswordGenerationError,
    PasswordPolicy,
    generate_password,
)
from app.services.vault_gateway import AuthenticatedVaultGateway
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
        self.local_settings_store = LocalSettingsStore()
        self.persisted_ui_settings = self.local_settings_store.load()

        self.api_client = VaultApiClient(self.persisted_ui_settings.api_base_url)
        self.desktop_service = VaultDesktopService(
            api_client=self.api_client,
            vault_gateway=AuthenticatedVaultGateway(self.api_client),
        )

        self.setWindowTitle(settings.app_name)
        self.resize(1120, 860)
        self.setStyleSheet(
            """
            QWidget {
                font-size: 11px;
            }
            QPushButton,
            QLineEdit,
            QTextEdit,
            QListWidget,
            QSpinBox,
            QLabel,
            QCheckBox,
            QTabBar::tab {
                font-size: 11px;
            }
            QPushButton {
                padding: 2px 6px;
            }
            """
        )

        self.status_label = QLabel("Press 'Probe API' or login.")
        self.status_label.setWordWrap(True)

        self.session_label = QLabel("No active session.")
        self.session_label.setWordWrap(True)

        self.identifier_input = QLineEdit()
        self.identifier_input.setText(self.persisted_ui_settings.identifier)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setText("strong-password")

        self.device_name_input = QLineEdit()
        self.device_name_input.setText(self.persisted_ui_settings.device_name)

        self.platform_input = QLineEdit()
        self.platform_input.setText(self.persisted_ui_settings.platform)

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

        self.create_credential_button = QPushButton("Create Credential")
        self.create_credential_button.clicked.connect(self.run_create_credential)

        self.reset_credential_payload_button = QPushButton("Reset Payload")
        self.reset_credential_payload_button.clicked.connect(self.reset_credential_create_fields)

        self.load_note_detail_button = QPushButton("Load Selected Note")
        self.load_note_detail_button.clicked.connect(self.load_note_detail)

        self.create_note_button = QPushButton("Create Note")
        self.create_note_button.clicked.connect(self.run_create_note)

        self.reset_note_payload_button = QPushButton("Reset Payload")
        self.reset_note_payload_button.clicked.connect(self.reset_note_create_fields)

        self.load_file_detail_button = QPushButton("Load Selected File")
        self.load_file_detail_button.clicked.connect(self.load_file_detail)

        self.pick_file_button = QPushButton("Pick File")
        self.pick_file_button.clicked.connect(self.run_pick_file)

        self.create_file_button = QPushButton("Create File")
        self.create_file_button.clicked.connect(self.run_create_file)

        self.reset_file_payload_button = QPushButton("Reset Payload")
        self.reset_file_payload_button.clicked.connect(self.reset_file_create_fields)

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

        self.credential_metadata_input = QTextEdit()
        self.credential_metadata_input.setPlaceholderText(
            'Optional JSON object, for example {"ciphertext_b64": "..."}'
        )
        self.credential_metadata_input.setMaximumHeight(90)

        self.credential_payload_input = QTextEdit()
        self.credential_payload_input.setPlaceholderText(
            'Required JSON object, for example {"ciphertext_b64": "..."}'
        )
        self.credential_payload_input.setMaximumHeight(90)

        self.credential_header_input = QTextEdit()
        self.credential_header_input.setPlaceholderText(
            'Required JSON object, for example {"nonce_b64": "..."}'
        )
        self.credential_header_input.setMaximumHeight(90)

        self.note_type_input = QLineEdit()
        self.note_type_input.setText("note")

        self.note_metadata_input = QTextEdit()
        self.note_metadata_input.setPlaceholderText(
            'Optional JSON object, for example {"ciphertext_b64": "..."}'
        )
        self.note_metadata_input.setMaximumHeight(90)

        self.note_payload_input = QTextEdit()
        self.note_payload_input.setPlaceholderText(
            'Required JSON object, for example {"ciphertext_b64": "..."}'
        )
        self.note_payload_input.setMaximumHeight(90)

        self.note_header_input = QTextEdit()
        self.note_header_input.setPlaceholderText(
            'Required JSON object, for example {"nonce_b64": "..."}'
        )
        self.note_header_input.setMaximumHeight(90)

        self.file_manifest_input = QTextEdit()
        self.file_manifest_input.setPlaceholderText(
            'Generated encrypted manifest JSON will appear here.'
        )
        self.file_manifest_input.setMaximumHeight(90)
        self.file_manifest_input.setReadOnly(True)

        self.file_header_input = QTextEdit()
        self.file_header_input.setPlaceholderText(
            'Generated encryption header JSON will appear here.'
        )
        self.file_header_input.setMaximumHeight(90)
        self.file_header_input.setReadOnly(True)

        self.file_chunks_input = QTextEdit()
        self.file_chunks_input.setPlaceholderText(
            'Generated encrypted chunks JSON will appear here.'
        )
        self.file_chunks_input.setMaximumHeight(130)
        self.file_chunks_input.setReadOnly(True)

        self.file_path_input = QLineEdit()
        self.file_path_input.setReadOnly(True)
        self.file_path_input.setPlaceholderText("No local file selected.")

        self.file_chunk_size_kib_input = QSpinBox()
        self.file_chunk_size_kib_input.setRange(1, 102400)
        self.file_chunk_size_kib_input.setValue(8192)
        self.file_chunk_size_kib_input.setSuffix(" KiB")

        self.file_master_key_b64_input = QLineEdit()
        self.file_master_key_b64_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.file_master_key_b64_input.setPlaceholderText(
            "Dev-only AES-256 master key in base64 (must decode to 32 bytes)."
        )

        self.reset_credential_create_fields()
        self.reset_note_create_fields()
        self.reset_file_create_fields()

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_credentials_tab(), "Credentials")
        self.tabs.addTab(self._build_notes_tab(), "Notes")
        self.tabs.addTab(self._build_files_tab(), "Files")
        self.tabs.setCurrentIndex(self.persisted_ui_settings.last_tab_index)

        self.password_length_input = QSpinBox()
        self.password_length_input.setRange(8, 256)
        self.password_length_input.setValue(24)

        self.use_uppercase_checkbox = QCheckBox("Uppercase")
        self.use_uppercase_checkbox.setChecked(True)

        self.use_lowercase_checkbox = QCheckBox("Lowercase")
        self.use_lowercase_checkbox.setChecked(True)

        self.use_digits_checkbox = QCheckBox("Digits")
        self.use_digits_checkbox.setChecked(True)

        self.use_symbols_checkbox = QCheckBox("Symbols")
        self.use_symbols_checkbox.setChecked(True)

        self.generated_password_output = QLineEdit()
        self.generated_password_output.setReadOnly(True)
        self.generated_password_output.setPlaceholderText("Generated password will appear here.")

        self.generate_password_button = QPushButton("Generate Password")
        self.generate_password_button.clicked.connect(self.run_generate_password)

        self.copy_generated_password_button = QPushButton("Copy Generated Password")
        self.copy_generated_password_button.clicked.connect(self.run_copy_generated_password)

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

        password_policy_layout = QHBoxLayout()
        password_policy_layout.addWidget(QLabel("Length"))
        password_policy_layout.addWidget(self.password_length_input)
        password_policy_layout.addWidget(self.use_uppercase_checkbox)
        password_policy_layout.addWidget(self.use_lowercase_checkbox)
        password_policy_layout.addWidget(self.use_digits_checkbox)
        password_policy_layout.addWidget(self.use_symbols_checkbox)

        password_actions_layout = QHBoxLayout()
        password_actions_layout.addWidget(self.generate_password_button)
        password_actions_layout.addWidget(self.copy_generated_password_button)

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"App: {settings.app_name}"))
        layout.addWidget(QLabel(f"Environment: {settings.environment}"))
        layout.addWidget(QLabel(f"API base URL: {self.persisted_ui_settings.api_base_url}"))
        layout.addWidget(self.probe_button)
        layout.addLayout(form_layout)
        layout.addLayout(auth_buttons_layout)
        layout.addWidget(self.status_label)
        layout.addWidget(self.session_label)
        layout.addWidget(QLabel("Dashboard"))
        layout.addLayout(dashboard_buttons_layout)
        layout.addWidget(self.tabs)
        layout.addWidget(QLabel("Password Tools"))
        layout.addLayout(password_policy_layout)
        layout.addWidget(self.generated_password_output)
        layout.addLayout(password_actions_layout)

        container = QWidget()
        container.setLayout(layout)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(container)
        self.setCentralWidget(scroll_area)

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

    def _build_credentials_tab(self) -> QWidget:
        create_buttons_layout = QHBoxLayout()
        create_buttons_layout.addWidget(self.load_credential_detail_button)
        create_buttons_layout.addWidget(self.create_credential_button)
        create_buttons_layout.addWidget(self.reset_credential_payload_button)

        create_hint_label = QLabel(
            "Create uses the current 'Device name' value from the auth form above. "
            "Until the crypto/UI flow is implemented, enter JSON objects manually."
        )
        create_hint_label.setWordWrap(True)

        create_form_layout = QFormLayout()
        create_form_layout.addRow("Metadata JSON", self.credential_metadata_input)
        create_form_layout.addRow("Payload JSON", self.credential_payload_input)
        create_form_layout.addRow("Header JSON", self.credential_header_input)

        left_layout = QVBoxLayout()
        left_layout.addLayout(create_buttons_layout)
        left_layout.addWidget(create_hint_label)
        left_layout.addLayout(create_form_layout)
        left_layout.addWidget(self.credentials_list)

        left_widget = QWidget()
        left_widget.setLayout(left_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_widget)
        splitter.addWidget(self.credentials_output)
        splitter.setSizes([520, 680])

        layout = QVBoxLayout()
        layout.addWidget(splitter)

        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def _build_notes_tab(self) -> QWidget:
        create_buttons_layout = QHBoxLayout()
        create_buttons_layout.addWidget(self.load_note_detail_button)
        create_buttons_layout.addWidget(self.create_note_button)
        create_buttons_layout.addWidget(self.reset_note_payload_button)

        create_hint_label = QLabel(
            "Create uses the current 'Device name' value from the auth form above. "
            "Until the crypto/UI flow is implemented, enter JSON objects manually."
        )
        create_hint_label.setWordWrap(True)

        create_form_layout = QFormLayout()
        create_form_layout.addRow("Note type", self.note_type_input)
        create_form_layout.addRow("Metadata JSON", self.note_metadata_input)
        create_form_layout.addRow("Payload JSON", self.note_payload_input)
        create_form_layout.addRow("Header JSON", self.note_header_input)

        left_layout = QVBoxLayout()
        left_layout.addLayout(create_buttons_layout)
        left_layout.addWidget(create_hint_label)
        left_layout.addLayout(create_form_layout)
        left_layout.addWidget(self.notes_list)

        left_widget = QWidget()
        left_widget.setLayout(left_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_widget)
        splitter.addWidget(self.notes_output)
        splitter.setSizes([520, 680])

        layout = QVBoxLayout()
        layout.addWidget(splitter)

        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def _build_files_tab(self) -> QWidget:
        create_buttons_layout = QHBoxLayout()
        create_buttons_layout.addWidget(self.load_file_detail_button)
        create_buttons_layout.addWidget(self.pick_file_button)
        create_buttons_layout.addWidget(self.create_file_button)
        create_buttons_layout.addWidget(self.reset_file_payload_button)

        create_hint_label = QLabel(
            "Pick a local file, then create an encrypted finalize payload locally. "
            "This UI now calls prepare/finalize and generates manifest/header/chunks automatically."
        )
        create_hint_label.setWordWrap(True)

        create_form_layout = QFormLayout()
        create_form_layout.addRow("Selected file", self.file_path_input)
        create_form_layout.addRow("Chunk size", self.file_chunk_size_kib_input)
        create_form_layout.addRow("Dev AES-256 key (base64)", self.file_master_key_b64_input)
        create_form_layout.addRow("Manifest JSON", self.file_manifest_input)
        create_form_layout.addRow("Header JSON", self.file_header_input)
        create_form_layout.addRow("Chunks JSON", self.file_chunks_input)

        left_layout = QVBoxLayout()
        left_layout.addLayout(create_buttons_layout)
        left_layout.addWidget(create_hint_label)
        left_layout.addLayout(create_form_layout)
        left_layout.addWidget(self.files_list)

        left_widget = QWidget()
        left_widget.setLayout(left_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_widget)
        splitter.addWidget(self.files_output)
        splitter.setSizes([520, 680])

        layout = QVBoxLayout()
        layout.addWidget(splitter)

        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def _save_ui_preferences(self) -> None:
        self.local_settings_store.save(
            PersistedUiSettings(
                api_base_url=self.persisted_ui_settings.api_base_url,
                identifier=self.identifier_input.text().strip() or "alice",
                device_name=self.device_name_input.text().strip() or "vault-desktop-dev",
                platform=self.platform_input.text().strip() or "linux",
                last_tab_index=self.tabs.currentIndex(),
            )
        )

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._save_ui_preferences()
        super().closeEvent(event)

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
        self._save_ui_preferences()

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
        self._save_ui_preferences()

    def run_close(self) -> None:
        self._save_ui_preferences()
        app = QApplication.instance()
        if app is not None:
            app.quit()
        else:
            self.close()

    def run_generate_password(self) -> None:
        policy = PasswordPolicy(
            length=self.password_length_input.value(),
            use_uppercase=self.use_uppercase_checkbox.isChecked(),
            use_lowercase=self.use_lowercase_checkbox.isChecked(),
            use_digits=self.use_digits_checkbox.isChecked(),
            use_symbols=self.use_symbols_checkbox.isChecked(),
        )

        try:
            password = generate_password(policy)
        except PasswordGenerationError as exc:
            self.status_label.setText(
                "Password generation failed.\n"
                f"Error: {exc}"
            )
            return

        self.generated_password_output.setText(password)
        self.status_label.setText(
            "Password generated locally.\n"
            f"Length: {len(password)}"
        )

    def run_copy_generated_password(self) -> None:
        password = self.generated_password_output.text()
        if not password:
            self.status_label.setText("Generate a password first.")
            return

        app = QApplication.instance()
        if app is None:
            self.status_label.setText("Clipboard is unavailable.")
            return

        clipboard = app.clipboard()
        clipboard.setText(password)
        self.status_label.setText("Generated password copied to clipboard.")

    def run_create_credential(self) -> None:
        device_name = self.device_name_input.text().strip()
        if not device_name:
            self.status_label.setText(
                "Credential creation failed.\n"
                "Error: Device name is empty."
            )
            return

        try:
            encrypted_metadata = self._parse_json_object_text(
                self.credential_metadata_input,
                field_name="Metadata JSON",
                allow_empty=True,
            )
            encrypted_payload = self._parse_json_object_text(
                self.credential_payload_input,
                field_name="Payload JSON",
                allow_empty=False,
            )
            encryption_header = self._parse_json_object_text(
                self.credential_header_input,
                field_name="Header JSON",
                allow_empty=False,
            )
        except ValueError as exc:
            self.status_label.setText(
                "Credential creation failed.\n"
                f"Error: {exc}"
            )
            return

        result = self.desktop_service.create_credential(
            device_name=device_name,
            encrypted_metadata=encrypted_metadata,
            encrypted_payload=encrypted_payload,
            encryption_header=encryption_header,
        )
        self._render_credential_create_result(result)

    def run_create_note(self) -> None:
        device_name = self.device_name_input.text().strip()
        if not device_name:
            self.status_label.setText(
                "Note creation failed.\n"
                "Error: Device name is empty."
            )
            return

        note_type = self.note_type_input.text().strip() or "note"

        try:
            encrypted_metadata = self._parse_json_object_text(
                self.note_metadata_input,
                field_name="Metadata JSON",
                allow_empty=True,
            )
            encrypted_payload = self._parse_json_object_text(
                self.note_payload_input,
                field_name="Payload JSON",
                allow_empty=False,
            )
            encryption_header = self._parse_json_object_text(
                self.note_header_input,
                field_name="Header JSON",
                allow_empty=False,
            )
        except ValueError as exc:
            self.status_label.setText(
                "Note creation failed.\n"
                f"Error: {exc}"
            )
            return

        result = self.desktop_service.create_note(
            device_name=device_name,
            note_type=note_type,
            encrypted_metadata=encrypted_metadata,
            encrypted_payload=encrypted_payload,
            encryption_header=encryption_header,
        )
        self._render_note_create_result(result)

    def run_pick_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Local File",
            "",
            "All files (*)",
        )
        if not file_path:
            return

        chunk_size_bytes = self.file_chunk_size_kib_input.value() * 1024

        try:
            result = inspect_plaintext_file(
                source_path=file_path,
                chunk_size_bytes=chunk_size_bytes,
            )
        except Exception as exc:
            self.status_label.setText(
                "File inspection failed.\n"
                f"Error: {exc}"
            )
            return

        self.file_path_input.setText(result.source_path)
        self.file_manifest_input.clear()
        self.file_header_input.clear()
        self.file_chunks_input.clear()
        self.status_label.setText(
            "Local file selected for encrypted upload.\n"
            f"Path: {result.source_path}\n"
            f"Size: {result.file_size_bytes} bytes\n"
            f"Chunk size: {result.chunk_size_bytes} bytes\n"
            f"Planned chunks: {result.chunk_count}"
        )

    def run_create_file(self) -> None:
        device_name = self.device_name_input.text().strip()
        if not device_name:
            self.status_label.setText(
                "File creation failed.\n"
                "Error: Device name is empty."
            )
            return

        source_path = self.file_path_input.text().strip()
        if not source_path:
            self.status_label.setText(
                "File creation failed.\n"
                "Error: No local file selected."
            )
            return

        master_key_b64 = self.file_master_key_b64_input.text().strip()
        if not master_key_b64:
            self.status_label.setText(
                "File creation failed.\n"
                "Error: Dev AES-256 key is empty."
            )
            return

        chunk_size_bytes = self.file_chunk_size_kib_input.value() * 1024

        try:
            inspection = inspect_plaintext_file(
                source_path=source_path,
                chunk_size_bytes=chunk_size_bytes,
            )
        except Exception as exc:
            self.files_output.setPlainText(
                "File inspection failed.\n"
                f"Error: {exc}"
            )
            self.status_label.setText(
                "File creation failed.\n"
                f"Error: {exc}"
            )
            return

        prepared_result = self.desktop_service.prepare_file(
            device_name=device_name,
            chunk_count=inspection.chunk_count,
        )
        if prepared_result.error:
            self.files_output.setPlainText(
                "File prepare failed.\n"
                f"Error: {prepared_result.error}"
            )
            self.status_label.setText(
                "File creation failed.\n"
                f"Error: {prepared_result.error}"
            )
            return

        try:
            finalize_payload = build_encrypted_file_finalize_payload(
                source_path=source_path,
                chunk_size_bytes=chunk_size_bytes,
                prepared_file=prepared_result.item or {},
                master_key_b64=master_key_b64,
            )
        except Exception as exc:
            self.files_output.setPlainText(
                "Local file encryption failed.\n"
                f"Error: {exc}"
            )
            self.status_label.setText(
                "File creation failed.\n"
                f"Error: {exc}"
            )
            return

        self._render_generated_file_payload_preview(finalize_payload)

        result = self.desktop_service.finalize_file(
            device_name=device_name,
            file_id=finalize_payload.file_id,
            file_version=finalize_payload.file_version,
            encrypted_manifest=finalize_payload.encrypted_manifest,
            encryption_header=finalize_payload.encryption_header,
            chunks=finalize_payload.chunks,
        )
        self._render_file_create_result(result)

    def reset_credential_create_fields(self) -> None:
        self.credential_metadata_input.setPlainText(
            json.dumps({"ciphertext_b64": "YWJj"}, indent=2)
        )
        self.credential_payload_input.setPlainText(
            json.dumps({"ciphertext_b64": "ZGVm"}, indent=2)
        )
        self.credential_header_input.setPlainText(
            json.dumps({"nonce_b64": "bm9uY2U="}, indent=2)
        )

    def reset_note_create_fields(self) -> None:
        self.note_type_input.setText("note")
        self.note_metadata_input.setPlainText(
            json.dumps({"ciphertext_b64": "YWJj"}, indent=2)
        )
        self.note_payload_input.setPlainText(
            json.dumps({"ciphertext_b64": "ZGVm"}, indent=2)
        )
        self.note_header_input.setPlainText(
            json.dumps({"nonce_b64": "bm9uY2U="}, indent=2)
        )

    def reset_file_create_fields(self) -> None:
        self.file_path_input.clear()
        self.file_chunk_size_kib_input.setValue(8192)
        self.file_master_key_b64_input.clear()
        self.file_manifest_input.clear()
        self.file_header_input.clear()
        self.file_chunks_input.clear()

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
        self._save_ui_preferences()

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

    def _render_credential_create_result(self, result: ObjectCreateResult) -> None:
        if result.error:
            self.credentials_output.setPlainText(
                f"Credential create failed.\nError: {result.error}"
            )
            self.status_label.setText(
                "Credential creation failed.\n"
                f"Error: {result.error}"
            )
            return

        item = result.item or {}
        credential_id = str(item.get("credential_id", ""))

        list_result = self.desktop_service.fetch_credentials()
        self._render_credentials(list_result)

        if credential_id and not list_result.error:
            self._select_credential_item_by_id(credential_id)

        self.credentials_output.setPlainText(format_credential_detail(item))
        self.tabs.setCurrentIndex(0)

        status_lines = [
            "Credential created.",
            f"Credential ID: {credential_id or '<unknown>'}",
        ]
        if list_result.error:
            status_lines.append(f"List refresh warning: {list_result.error}")

        self.status_label.setText("\n".join(status_lines))
        self._save_ui_preferences()

    def _render_note_create_result(self, result: ObjectCreateResult) -> None:
        if result.error:
            self.notes_output.setPlainText(
                f"Note create failed.\nError: {result.error}"
            )
            self.status_label.setText(
                "Note creation failed.\n"
                f"Error: {result.error}"
            )
            return

        item = result.item or {}
        note_id = str(item.get("note_id", ""))

        list_result = self.desktop_service.fetch_notes()
        self._render_notes(list_result)

        if note_id and not list_result.error:
            self._select_note_item_by_id(note_id)

        self.notes_output.setPlainText(format_note_detail(item))
        self.tabs.setCurrentIndex(1)

        status_lines = [
            "Note created.",
            f"Note ID: {note_id or '<unknown>'}",
        ]
        if list_result.error:
            status_lines.append(f"List refresh warning: {list_result.error}")

        self.status_label.setText("\n".join(status_lines))
        self._save_ui_preferences()

    def _render_generated_file_payload_preview(self, finalize_payload) -> None:
        self.file_manifest_input.setPlainText(
            json.dumps(finalize_payload.encrypted_manifest, indent=2)
        )
        self.file_header_input.setPlainText(
            json.dumps(finalize_payload.encryption_header, indent=2)
        )

        chunks = list(finalize_payload.chunks)
        should_render_full_chunks = (
            len(chunks) <= 8
            and all(len(str(chunk.get("ciphertext_b64", ""))) <= 2048 for chunk in chunks)
        )

        if should_render_full_chunks:
            self.file_chunks_input.setPlainText(json.dumps(chunks, indent=2))
            return

        preview_count = min(5, len(chunks))
        preview = []
        for chunk in chunks[:preview_count]:
            preview.append(
                {
                    "chunk_index": chunk.get("chunk_index"),
                    "object_key": chunk.get("object_key"),
                    "ciphertext_sha256_hex": chunk.get("ciphertext_sha256_hex"),
                    "ciphertext_b64_length": len(str(chunk.get("ciphertext_b64", ""))),
                }
            )

        summary = {
            "display_mode": "summary_only",
            "reason": "encrypted chunk payload too large for QTextEdit rendering",
            "file_id": finalize_payload.file_id,
            "file_version": finalize_payload.file_version,
            "total_plaintext_size": finalize_payload.total_plaintext_size,
            "chunk_size_bytes": finalize_payload.chunk_size_bytes,
            "chunk_count": len(chunks),
            "preview_count": preview_count,
            "preview": preview,
        }
        self.file_chunks_input.setPlainText(json.dumps(summary, indent=2))

    def _render_file_create_result(self, result: ObjectCreateResult) -> None:
        if result.error:
            self.files_output.setPlainText(
                f"File create failed.\nError: {result.error}"
            )
            self.status_label.setText(
                "File creation failed.\n"
                f"Error: {result.error}"
            )
            return

        item = result.item or {}
        file_id = str(item.get("file_id", ""))

        list_result = self.desktop_service.fetch_files()
        self._render_files(list_result)

        if file_id and not list_result.error:
            self._select_file_item_by_id(file_id)

        self.files_output.setPlainText(format_file_detail(item))
        self.tabs.setCurrentIndex(2)

        status_lines = [
            "File created.",
            f"File ID: {file_id or '<unknown>'}",
        ]
        if list_result.error:
            status_lines.append(f"List refresh warning: {list_result.error}")

        self.status_label.setText("\n".join(status_lines))
        self._save_ui_preferences()

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

    def _parse_json_object_text(
        self,
        widget: QTextEdit,
        *,
        field_name: str,
        allow_empty: bool,
    ) -> dict | None:
        raw = widget.toPlainText().strip()
        if not raw:
            if allow_empty:
                return None
            raise ValueError(f"{field_name} is empty.")

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{field_name} must be valid JSON. "
                f"Error: {exc.msg} at line {exc.lineno} column {exc.colno}."
            ) from exc

        if parsed is None and allow_empty:
            return None

        if not isinstance(parsed, dict):
            raise ValueError(f"{field_name} must be a JSON object.")

        return parsed

    def _parse_json_array_text(
        self,
        widget: QTextEdit,
        *,
        field_name: str,
        allow_empty: bool,
    ) -> list[dict]:
        raw = widget.toPlainText().strip()
        if not raw:
            if allow_empty:
                return []
            raise ValueError(f"{field_name} is empty.")

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{field_name} must be valid JSON. "
                f"Error: {exc.msg} at line {exc.lineno} column {exc.colno}."
            ) from exc

        if not isinstance(parsed, list):
            raise ValueError(f"{field_name} must be a JSON array.")

        if not parsed and not allow_empty:
            raise ValueError(f"{field_name} must not be empty.")

        for index, item in enumerate(parsed):
            if not isinstance(item, dict):
                raise ValueError(f"{field_name} item {index} must be a JSON object.")

        return parsed

    def _select_credential_item_by_id(self, credential_id: str) -> None:
        for index in range(self.credentials_list.count()):
            item = self.credentials_list.item(index)
            if item.data(Qt.ItemDataRole.UserRole) == credential_id:
                self.credentials_list.setCurrentRow(index)
                return

    def _select_note_item_by_id(self, note_id: str) -> None:
        for index in range(self.notes_list.count()):
            item = self.notes_list.item(index)
            if item.data(Qt.ItemDataRole.UserRole) == note_id:
                self.notes_list.setCurrentRow(index)
                return

    def _select_file_item_by_id(self, file_id: str) -> None:
        for index in range(self.files_list.count()):
            item = self.files_list.item(index)
            if item.data(Qt.ItemDataRole.UserRole) == file_id:
                self.files_list.setCurrentRow(index)
                return

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
