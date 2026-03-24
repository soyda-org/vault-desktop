from __future__ import annotations

import json
import os

from PySide6.QtCore import QThread, Qt, QEvent, QTimer

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
    QProgressBar,
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
from app.services.file_crypto_bridge import inspect_plaintext_file
from app.services.item_crypto_bridge import (
    build_encrypted_item_finalize_payload,
    decrypt_item_detail,
)
from app.services.password_generator import (
    PasswordGenerationError,
    PasswordPolicy,
    generate_password,
)
from app.services.vault_gateway import AuthenticatedVaultGateway
from app.ui.file_download_worker import FileDownloadWorker
from app.ui.file_upload_worker import FileUploadWorker
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
        self.resize(1180, 780)
        self.setMinimumSize(960, 640)
        self.setStyleSheet(
            """
            QWidget {
                font-size: 10px;
            }
            QPushButton,
            QLineEdit,
            QTextEdit,
            QListWidget,
            QSpinBox,
            QLabel,
            QCheckBox,
            QTabBar::tab {
                font-size: 10px;
            }
            QPushButton {
                padding: 1px 5px;
            }
            QTabBar::tab {
                padding: 3px 8px;
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
        self.load_credential_detail_button.setEnabled(False)

        self.create_credential_button = QPushButton("Create Credential")
        self.create_credential_button.clicked.connect(self.run_create_credential)

        self.update_credential_button = QPushButton("Update Credential")
        self.update_credential_button.clicked.connect(self.run_update_credential)
        self.update_credential_button.setEnabled(False)

        self.delete_credential_button = QPushButton("Delete Credential")
        self.delete_credential_button.clicked.connect(self.run_delete_credential)
        self.delete_credential_button.setEnabled(False)

        self.reset_credential_payload_button = QPushButton("Reset Payload")
        self.reset_credential_payload_button.clicked.connect(self.reset_credential_create_fields)

        self.load_note_detail_button = QPushButton("Load Selected Note")
        self.load_note_detail_button.clicked.connect(self.load_note_detail)
        self.load_note_detail_button.setEnabled(False)

        self.create_note_button = QPushButton("Create Note")
        self.create_note_button.clicked.connect(self.run_create_note)

        self.update_note_button = QPushButton("Update Note")
        self.update_note_button.clicked.connect(self.run_update_note)
        self.update_note_button.setEnabled(False)

        self.delete_note_button = QPushButton("Delete Note")
        self.delete_note_button.clicked.connect(self.run_delete_note)
        self.delete_note_button.setEnabled(False)

        self.reset_note_payload_button = QPushButton("Reset Payload")
        self.reset_note_payload_button.clicked.connect(self.reset_note_create_fields)

        self.load_file_detail_button = QPushButton("Load Selected File")
        self.load_file_detail_button.clicked.connect(self.load_file_detail)
        self.load_file_detail_button.setEnabled(False)

        self.pick_file_button = QPushButton("Pick File")
        self.pick_file_button.clicked.connect(self.run_pick_file)

        self.create_file_button = QPushButton("Create File")
        self.create_file_button.clicked.connect(self.run_create_file)
        self.create_file_button.setEnabled(False)

        self.cancel_file_upload_button = QPushButton("Cancel Upload")
        self.cancel_file_upload_button.clicked.connect(self.run_cancel_file_upload)
        self.cancel_file_upload_button.setEnabled(False)

        self.pick_download_target_button = QPushButton("Pick Save Path")
        self.pick_download_target_button.clicked.connect(self.run_pick_download_target)

        self.download_file_button = QPushButton("Download File")
        self.download_file_button.clicked.connect(self.run_download_file)
        self.download_file_button.setEnabled(False)

        self.cancel_file_download_button = QPushButton("Cancel Download")
        self.cancel_file_download_button.clicked.connect(self.run_cancel_file_download)
        self.cancel_file_download_button.setEnabled(False)

        self.reset_file_payload_button = QPushButton("Reset Payload")
        self.reset_file_payload_button.clicked.connect(self.reset_file_create_fields)

        self.file_upload_thread: QThread | None = None
        self.file_upload_worker: FileUploadWorker | None = None
        self.file_download_thread: QThread | None = None
        self.file_download_worker: FileDownloadWorker | None = None

        self.selected_credential_id: str | None = None
        self.selected_credential_current_version: int | None = None
        self.selected_note_id: str | None = None
        self.selected_note_current_version: int | None = None

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
            'Optional plaintext JSON object, for example {"label": "Personal"}'
        )
        self.credential_metadata_input.setMaximumHeight(90)

        self.credential_payload_input = QTextEdit()
        self.credential_payload_input.setPlaceholderText(
            'Required plaintext JSON object, for example {"username": "alice", "secret": "s3cr3t"}'
        )
        self.credential_payload_input.setMaximumHeight(90)

        self.credential_header_input = QTextEdit()
        self.credential_header_input.setPlaceholderText(
            "Generated encryption header JSON will appear here after local encryption."
        )
        self.credential_header_input.setMaximumHeight(90)
        self.credential_header_input.setReadOnly(True)

        self.note_type_input = QLineEdit()
        self.note_type_input.setText("note")

        self.note_metadata_input = QTextEdit()
        self.note_metadata_input.setPlaceholderText(
            'Optional plaintext JSON object, for example {"tags": ["todo"]}'
        )
        self.note_metadata_input.setMaximumHeight(90)

        self.note_payload_input = QTextEdit()
        self.note_payload_input.setPlaceholderText(
            'Required plaintext JSON object, for example {"title": "todo", "content": "buy milk"}'
        )
        self.note_payload_input.setMaximumHeight(90)

        self.note_header_input = QTextEdit()
        self.note_header_input.setPlaceholderText(
            "Generated encryption header JSON will appear here after local encryption."
        )
        self.note_header_input.setMaximumHeight(90)
        self.note_header_input.setReadOnly(True)

        self.file_manifest_input = QTextEdit()
        self.file_manifest_input.setPlaceholderText(
            'Generated encrypted manifest JSON will appear here.'
        )
        self.file_manifest_input.setMaximumHeight(72)
        self.file_manifest_input.setReadOnly(True)

        self.file_header_input = QTextEdit()
        self.file_header_input.setPlaceholderText(
            'Generated encryption header JSON will appear here.'
        )
        self.file_header_input.setMaximumHeight(72)
        self.file_header_input.setReadOnly(True)

        self.file_chunks_input = QTextEdit()
        self.file_chunks_input.setPlaceholderText(
            'Generated encrypted chunks JSON will appear here.'
        )
        self.file_chunks_input.setMaximumHeight(96)
        self.file_chunks_input.setReadOnly(True)

        self.file_path_input = QLineEdit()
        self.file_path_input.setReadOnly(True)
        self.file_path_input.setPlaceholderText("No local file selected.")

        self.file_download_target_input = QLineEdit()
        self.file_download_target_input.setReadOnly(True)
        self.file_download_target_input.setPlaceholderText("No local download target selected.")

        self.file_chunk_size_kib_input = QSpinBox()
        self.file_chunk_size_kib_input.setRange(1, 102400)
        self.file_chunk_size_kib_input.setValue(8192)
        self.file_chunk_size_kib_input.setSuffix(" KiB")

        self.vault_pin_input = QLineEdit()
        self.vault_pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.vault_pin_input.setPlaceholderText(
            "Everyday use target: unlock with PIN (scaffold only for now)."
        )

        self.unlock_vault_pin_button = QPushButton("Unlock with PIN")
        self.unlock_vault_pin_button.clicked.connect(self.run_unlock_vault_with_pin)

        self.enroll_vault_pin_button = QPushButton("Enroll PIN on This Device")
        self.enroll_vault_pin_button.clicked.connect(self.run_enroll_vault_pin)

        self.remove_vault_pin_button = QPushButton("Remove PIN from This Device")
        self.remove_vault_pin_button.clicked.connect(self.run_remove_vault_pin)

        self.lock_now_button = QPushButton("Lock Now")
        self.lock_now_button.clicked.connect(self.run_lock_vault_now)

        self.toggle_advanced_recovery_button = QPushButton("Show Advanced Recovery")
        self.toggle_advanced_recovery_button.clicked.connect(
            self.toggle_advanced_recovery
        )

        self.file_master_key_b64_input = QLineEdit()
        self.file_master_key_b64_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.file_master_key_b64_input.setPlaceholderText(
            "Temporary recovery/dev path: enter the vault key to unlock this session."
        )

        self.unlock_session_key_button = QPushButton("Unlock with Recovery Key")
        self.unlock_session_key_button.clicked.connect(self.run_unlock_session_key)

        self.clear_session_key_button = QPushButton("Clear Vault Key")
        self.clear_session_key_button.clicked.connect(self.run_clear_session_key)

        self.file_upload_progress = QProgressBar()
        self.file_upload_progress.setRange(0, 100)
        self.file_upload_progress.setValue(0)
        self.file_upload_progress.setFormat("%p%")

        self.file_download_progress = QProgressBar()
        self.file_download_progress.setRange(0, 100)
        self.file_download_progress.setValue(0)
        self.file_download_progress.setFormat("%p%")

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
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setHorizontalSpacing(6)
        form_layout.setVerticalSpacing(4)
        form_layout.addRow("Identifier", self.identifier_input)
        form_layout.addRow("Password", self.password_input)
        form_layout.addRow("Device name", self.device_name_input)
        form_layout.addRow("Platform", self.platform_input)

        auth_buttons_layout = QHBoxLayout()
        auth_buttons_layout.setContentsMargins(0, 0, 0, 0)
        auth_buttons_layout.setSpacing(4)
        auth_buttons_layout.addWidget(self.login_button)
        auth_buttons_layout.addWidget(self.logout_button)
        auth_buttons_layout.addWidget(self.close_button)

        vault_row = QHBoxLayout()
        vault_row.setContentsMargins(0, 0, 0, 0)
        vault_row.setSpacing(4)
        vault_row.addWidget(QLabel("Vault"))
        vault_row.addWidget(self.vault_pin_input, 1)
        vault_row.addWidget(self.unlock_vault_pin_button)
        vault_row.addWidget(self.enroll_vault_pin_button)
        vault_row.addWidget(self.remove_vault_pin_button)
        vault_row.addWidget(self.lock_now_button)
        vault_row.addWidget(self.toggle_advanced_recovery_button)

        self.pin_bootstrap_status_label = QLabel()
        self.pin_bootstrap_status_label.setWordWrap(True)

        self.vault_unlock_source_label = QLabel()
        self.vault_unlock_source_label.setWordWrap(True)

        advanced_recovery_row = QHBoxLayout()
        advanced_recovery_row.setContentsMargins(0, 0, 0, 0)
        advanced_recovery_row.setSpacing(4)
        advanced_recovery_row.addWidget(QLabel("Recovery key"))
        advanced_recovery_row.addWidget(self.file_master_key_b64_input, 1)
        advanced_recovery_row.addWidget(self.unlock_session_key_button)
        advanced_recovery_row.addWidget(self.clear_session_key_button)

        self.advanced_recovery_widget = QWidget()
        self.advanced_recovery_widget.setLayout(advanced_recovery_row)
        self.advanced_recovery_widget.setVisible(False)

        vault_hint_label = QLabel(
            "Vault controls are global for this session. Everyday use can enroll a PIN on this device after unlocking once with the recovery key. "
            "The recovery key path below remains the advanced fallback until real PIN-based unwrap is fully in place."
        )
        vault_hint_label.setWordWrap(True)

        dashboard_buttons_layout = QHBoxLayout()
        dashboard_buttons_layout.setContentsMargins(0, 0, 0, 0)
        dashboard_buttons_layout.setSpacing(4)
        dashboard_buttons_layout.addWidget(self.load_credentials_button)
        dashboard_buttons_layout.addWidget(self.load_notes_button)
        dashboard_buttons_layout.addWidget(self.load_files_button)
        dashboard_buttons_layout.addWidget(self.load_all_button)

        password_policy_layout = QHBoxLayout()
        password_policy_layout.setContentsMargins(0, 0, 0, 0)
        password_policy_layout.setSpacing(4)
        password_policy_layout.addWidget(QLabel("Length"))
        password_policy_layout.addWidget(self.password_length_input)
        password_policy_layout.addWidget(self.use_uppercase_checkbox)
        password_policy_layout.addWidget(self.use_lowercase_checkbox)
        password_policy_layout.addWidget(self.use_digits_checkbox)
        password_policy_layout.addWidget(self.use_symbols_checkbox)

        header_label = QLabel(
            f"App: {settings.app_name} | Environment: {settings.environment} | API: {self.persisted_ui_settings.api_base_url}"
        )
        header_label.setWordWrap(True)

        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(4)
        header_layout.addWidget(header_label, 1)
        header_layout.addWidget(self.probe_button)

        dashboard_row = QHBoxLayout()
        dashboard_row.setContentsMargins(0, 0, 0, 0)
        dashboard_row.setSpacing(4)
        dashboard_row.addWidget(QLabel("Dashboard"))
        dashboard_row.addLayout(dashboard_buttons_layout, 1)

        password_row = QHBoxLayout()
        password_row.setContentsMargins(0, 0, 0, 0)
        password_row.setSpacing(4)
        password_row.addWidget(QLabel("Password Tools"))
        password_row.addLayout(password_policy_layout)
        password_row.addWidget(self.generated_password_output, 1)
        password_row.addWidget(self.generate_password_button)
        password_row.addWidget(self.copy_generated_password_button)

        layout = QVBoxLayout()
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)
        layout.addLayout(header_layout)
        layout.addLayout(form_layout)
        layout.addLayout(auth_buttons_layout)
        layout.addLayout(vault_row)
        layout.addWidget(self.pin_bootstrap_status_label)
        layout.addWidget(self.vault_unlock_source_label)
        layout.addWidget(self.advanced_recovery_widget)
        layout.addWidget(vault_hint_label)
        layout.addWidget(self.status_label)
        layout.addWidget(self.session_label)
        layout.addLayout(dashboard_row)
        layout.addWidget(self.tabs, 1)
        layout.addLayout(password_row)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.credentials_list.currentItemChanged.connect(lambda *_: self._refresh_action_states())
        self.notes_list.currentItemChanged.connect(lambda *_: self._refresh_action_states())
        self.files_list.currentItemChanged.connect(lambda *_: self._refresh_action_states())
        self.file_path_input.textChanged.connect(lambda *_: self._refresh_action_states())
        self.file_download_target_input.textChanged.connect(lambda *_: self._refresh_action_states())
        self.vault_pin_input.textChanged.connect(lambda *_: self._refresh_action_states())

        self.vault_auto_lock_timeout_ms = self._read_timeout_ms(
            "VAULT_DESKTOP_AUTO_LOCK_SECONDS",
            default_seconds=180,
            minimum_seconds=5,
        )
        self.session_auto_logout_timeout_ms = self._read_timeout_ms(
            "VAULT_DESKTOP_AUTO_LOGOUT_SECONDS",
            default_seconds=720,
            minimum_seconds=15,
        )

        self.vault_auto_lock_timer = QTimer(self)
        self.vault_auto_lock_timer.setSingleShot(True)
        self.vault_auto_lock_timer.timeout.connect(self._handle_vault_auto_lock_timeout)

        self.session_auto_logout_timer = QTimer(self)
        self.session_auto_logout_timer.setSingleShot(True)
        self.session_auto_logout_timer.timeout.connect(self._handle_session_auto_logout_timeout)

        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)

        self.refresh_session_label()
        self._refresh_action_states()
        self._refresh_idle_policy()

    def _build_tab(
        self,
        object_list: QListWidget,
        detail_button: QPushButton,
        output: QTextEdit,
    ) -> QWidget:
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)
        left_layout.addWidget(detail_button)
        left_layout.addWidget(object_list)

        left_widget = QWidget()
        left_widget.setLayout(left_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(left_widget)
        splitter.addWidget(output)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([360, 700])

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(splitter)

        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def _build_credentials_tab(self) -> QWidget:
        create_buttons_layout = QHBoxLayout()
        create_buttons_layout.addWidget(self.load_credential_detail_button)
        create_buttons_layout.addWidget(self.create_credential_button)
        create_buttons_layout.addWidget(self.update_credential_button)
        create_buttons_layout.addWidget(self.delete_credential_button)
        create_buttons_layout.addWidget(self.reset_credential_payload_button)

        create_hint_label = QLabel(
            "Create/update uses the current 'Device name' value and the unlocked session vault key. "
            "Create reserves a new credential ID; load a credential detail to prefill plaintext editors before saving a new encrypted version."
        )
        create_hint_label.setWordWrap(True)

        create_form_layout = QFormLayout()
        create_form_layout.addRow("Metadata JSON (plaintext)", self.credential_metadata_input)
        create_form_layout.addRow("Payload JSON (plaintext)", self.credential_payload_input)
        create_form_layout.addRow("Generated header JSON", self.credential_header_input)

        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)
        left_layout.addLayout(create_buttons_layout)
        left_layout.addWidget(create_hint_label)
        left_layout.addLayout(create_form_layout)
        left_layout.addWidget(self.credentials_list)

        left_widget = QWidget()
        left_widget.setLayout(left_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(left_widget)
        splitter.addWidget(self.credentials_output)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 4)
        splitter.setSizes([520, 680])

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(splitter)

        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def _build_notes_tab(self) -> QWidget:
        create_buttons_layout = QHBoxLayout()
        create_buttons_layout.addWidget(self.load_note_detail_button)
        create_buttons_layout.addWidget(self.create_note_button)
        create_buttons_layout.addWidget(self.update_note_button)
        create_buttons_layout.addWidget(self.delete_note_button)
        create_buttons_layout.addWidget(self.reset_note_payload_button)

        create_hint_label = QLabel(
            "Create/update uses the current 'Device name' value and the unlocked session vault key. "
            "Create reserves a new note ID; load a note detail to prefill plaintext editors before saving a new encrypted version."
        )
        create_hint_label.setWordWrap(True)

        create_form_layout = QFormLayout()
        create_form_layout.addRow("Note type", self.note_type_input)
        create_form_layout.addRow("Metadata JSON (plaintext)", self.note_metadata_input)
        create_form_layout.addRow("Payload JSON (plaintext)", self.note_payload_input)
        create_form_layout.addRow("Generated header JSON", self.note_header_input)

        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)
        left_layout.addLayout(create_buttons_layout)
        left_layout.addWidget(create_hint_label)
        left_layout.addLayout(create_form_layout)
        left_layout.addWidget(self.notes_list)

        left_widget = QWidget()
        left_widget.setLayout(left_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(left_widget)
        splitter.addWidget(self.notes_output)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 4)
        splitter.setSizes([520, 680])

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(splitter)

        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def _build_files_tab(self) -> QWidget:
        create_buttons_layout = QHBoxLayout()
        create_buttons_layout.setContentsMargins(0, 0, 0, 0)
        create_buttons_layout.setSpacing(4)
        create_buttons_layout.addWidget(self.load_file_detail_button)
        create_buttons_layout.addWidget(self.pick_file_button)
        create_buttons_layout.addWidget(self.create_file_button)
        create_buttons_layout.addWidget(self.cancel_file_upload_button)
        create_buttons_layout.addWidget(self.pick_download_target_button)
        create_buttons_layout.addWidget(self.download_file_button)
        create_buttons_layout.addWidget(self.cancel_file_download_button)
        create_buttons_layout.addWidget(self.reset_file_payload_button)

        create_hint_label = QLabel(
            "Pick a local file for encrypted upload, or select a vault file and download/decrypt it locally. "
            "Use the global Vault controls above to unlock once per session; that same unlock state applies to credentials, notes, and files."
        )
        create_hint_label.setWordWrap(True)

        path_row = QHBoxLayout()
        path_row.setContentsMargins(0, 0, 0, 0)
        path_row.setSpacing(4)
        path_row.addWidget(QLabel("Selected file"))
        path_row.addWidget(self.file_path_input, 1)

        target_row = QHBoxLayout()
        target_row.setContentsMargins(0, 0, 0, 0)
        target_row.setSpacing(4)
        target_row.addWidget(QLabel("Download target"))
        target_row.addWidget(self.file_download_target_input, 1)

        runtime_row = QHBoxLayout()
        runtime_row.setContentsMargins(0, 0, 0, 0)
        runtime_row.setSpacing(4)
        runtime_row.addWidget(QLabel("Chunk size"))
        runtime_row.addWidget(self.file_chunk_size_kib_input)
        runtime_row.addStretch(1)

        progress_row = QHBoxLayout()
        progress_row.setContentsMargins(0, 0, 0, 0)
        progress_row.setSpacing(4)
        progress_row.addWidget(QLabel("Upload"))
        progress_row.addWidget(self.file_upload_progress, 1)
        progress_row.addWidget(QLabel("Download"))
        progress_row.addWidget(self.file_download_progress, 1)

        manifest_layout = QVBoxLayout()
        manifest_layout.setContentsMargins(0, 0, 0, 0)
        manifest_layout.setSpacing(2)
        manifest_layout.addWidget(QLabel("Manifest JSON"))
        manifest_layout.addWidget(self.file_manifest_input)

        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(2)
        header_layout.addWidget(QLabel("Header JSON"))
        header_layout.addWidget(self.file_header_input)

        chunks_layout = QVBoxLayout()
        chunks_layout.setContentsMargins(0, 0, 0, 0)
        chunks_layout.setSpacing(2)
        chunks_layout.addWidget(QLabel("Chunks JSON"))
        chunks_layout.addWidget(self.file_chunks_input)

        previews_row = QHBoxLayout()
        previews_row.setContentsMargins(0, 0, 0, 0)
        previews_row.setSpacing(4)
        previews_row.addLayout(manifest_layout, 1)
        previews_row.addLayout(header_layout, 1)
        previews_row.addLayout(chunks_layout, 1)

        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)
        left_layout.addLayout(create_buttons_layout)
        left_layout.addWidget(create_hint_label)
        left_layout.addLayout(path_row)
        left_layout.addLayout(target_row)
        left_layout.addLayout(runtime_row)
        left_layout.addLayout(progress_row)
        left_layout.addLayout(previews_row)
        left_layout.addWidget(self.files_list)

        left_widget = QWidget()
        left_widget.setLayout(left_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(left_widget)
        splitter.addWidget(self.files_output)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 4)
        splitter.setSizes([560, 640])

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(splitter)

        widget = QWidget()
        widget.setLayout(layout)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(widget)
        return scroll_area

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
        if self._is_file_job_running():
            self.status_label.setText(
                "A file job is still running.\n"
                "Wait for completion before closing the app."
            )
            event.ignore()
            return
        self._stop_idle_timers()
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
        self.file_master_key_b64_input.clear()
        self.refresh_session_label()
        self._refresh_action_states()
        self._refresh_idle_policy()
        self._save_ui_preferences()

    def run_logout(self) -> None:
        if self._is_file_job_running():
            self.status_label.setText(
                "A file job is still running.\n"
                "Wait for completion before logging out."
            )
            return
        self._perform_local_logout("Session cleared locally.")

    def run_close(self) -> None:
        if self._is_file_job_running():
            self.status_label.setText(
                "A file job is still running.\n"
                "Wait for completion before closing the app."
            )
            return
        self._stop_idle_timers()
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

        master_key_b64 = self.desktop_service.current_session_vault_master_key()
        if not master_key_b64:
            self.status_label.setText(
                "Credential creation failed.\n"
                "Error: Session vault key is not unlocked."
            )
            return

        try:
            plaintext_metadata = self._parse_json_object_text(
                self.credential_metadata_input,
                field_name="Metadata JSON (plaintext)",
                allow_empty=True,
            )
            plaintext_payload = self._parse_json_object_text(
                self.credential_payload_input,
                field_name="Payload JSON (plaintext)",
                allow_empty=False,
            )
        except ValueError as exc:
            self.status_label.setText(
                "Credential creation failed.\n"
                f"Error: {exc}"
            )
            return

        prepare_result = self.desktop_service.prepare_credential(device_name=device_name)
        if prepare_result.error:
            self.credentials_output.setPlainText(
                f"Credential prepare failed.\nError: {prepare_result.error}"
            )
            self.status_label.setText(
                "Credential creation failed.\n"
                f"Error: {prepare_result.error}"
            )
            return

        prepared_item = prepare_result.item or {}
        credential_id = str(prepared_item.get("credential_id", "")).strip()
        try:
            credential_version = int(prepared_item.get("credential_version"))
        except (TypeError, ValueError):
            credential_version = 0

        if not credential_id or credential_version < 1:
            self.status_label.setText(
                "Credential creation failed.\n"
                "Error: Invalid prepare response."
            )
            return

        try:
            encrypted = build_encrypted_item_finalize_payload(
                object_type="credential",
                object_id=credential_id,
                object_version=credential_version,
                plaintext_metadata=plaintext_metadata,
                plaintext_payload=plaintext_payload,
                master_key_b64=master_key_b64,
            )
        except Exception as exc:
            self.status_label.setText(
                "Credential creation failed.\n"
                f"Error: {exc}"
            )
            return

        self.credential_header_input.setPlainText(
            json.dumps(encrypted.encryption_header, indent=2)
        )

        result = self.desktop_service.finalize_credential(
            device_name=device_name,
            credential_id=credential_id,
            credential_version=credential_version,
            encrypted_metadata=encrypted.encrypted_metadata,
            encrypted_payload=encrypted.encrypted_payload,
            encryption_header=encrypted.encryption_header,
        )

        if result.error is None and result.item is not None:
            decorated_item = dict(result.item)
            decorated_item["plaintext_metadata"] = plaintext_metadata
            decorated_item["plaintext_payload"] = plaintext_payload
            result = ObjectCreateResult(
                item=decorated_item,
                error=None,
                status_code=result.status_code,
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

        master_key_b64 = self.desktop_service.current_session_vault_master_key()
        if not master_key_b64:
            self.status_label.setText(
                "Note creation failed.\n"
                "Error: Session vault key is not unlocked."
            )
            return

        note_type = self.note_type_input.text().strip() or "note"

        try:
            plaintext_metadata = self._parse_json_object_text(
                self.note_metadata_input,
                field_name="Metadata JSON (plaintext)",
                allow_empty=True,
            )
            plaintext_payload = self._parse_json_object_text(
                self.note_payload_input,
                field_name="Payload JSON (plaintext)",
                allow_empty=False,
            )
        except ValueError as exc:
            self.status_label.setText(
                "Note creation failed.\n"
                f"Error: {exc}"
            )
            return

        prepare_result = self.desktop_service.prepare_note(
            device_name=device_name,
            note_type=note_type,
        )
        if prepare_result.error:
            self.notes_output.setPlainText(
                f"Note prepare failed.\nError: {prepare_result.error}"
            )
            self.status_label.setText(
                "Note creation failed.\n"
                f"Error: {prepare_result.error}"
            )
            return

        prepared_item = prepare_result.item or {}
        note_id = str(prepared_item.get("note_id", "")).strip()
        try:
            note_version = int(prepared_item.get("note_version"))
        except (TypeError, ValueError):
            note_version = 0

        if not note_id or note_version < 1:
            self.status_label.setText(
                "Note creation failed.\n"
                "Error: Invalid prepare response."
            )
            return

        try:
            encrypted = build_encrypted_item_finalize_payload(
                object_type="note",
                object_id=note_id,
                object_version=note_version,
                plaintext_metadata=plaintext_metadata,
                plaintext_payload=plaintext_payload,
                master_key_b64=master_key_b64,
            )
        except Exception as exc:
            self.status_label.setText(
                "Note creation failed.\n"
                f"Error: {exc}"
            )
            return

        self.note_header_input.setPlainText(
            json.dumps(encrypted.encryption_header, indent=2)
        )

        result = self.desktop_service.finalize_note(
            device_name=device_name,
            note_id=note_id,
            note_version=note_version,
            encrypted_metadata=encrypted.encrypted_metadata,
            encrypted_payload=encrypted.encrypted_payload,
            encryption_header=encrypted.encryption_header,
        )

        if result.error is None and result.item is not None:
            decorated_item = dict(result.item)
            decorated_item["plaintext_metadata"] = plaintext_metadata
            decorated_item["plaintext_payload"] = plaintext_payload
            result = ObjectCreateResult(
                item=decorated_item,
                error=None,
                status_code=result.status_code,
            )

        self._render_note_create_result(result)

    def run_update_credential(self) -> None:
        device_name = self.device_name_input.text().strip()
        if not device_name:
            self.status_label.setText(
                "Credential update failed.\n"
                "Error: Device name is empty."
            )
            return

        credential_id = self.selected_credential_id
        current_version = self.selected_credential_current_version
        if not credential_id or current_version is None:
            self.status_label.setText(
                "Credential update failed.\n"
                "Error: Load a credential detail first."
            )
            return

        master_key_b64 = self.desktop_service.current_session_vault_master_key()
        if not master_key_b64:
            self.status_label.setText(
                "Credential update failed.\n"
                "Error: Session vault key is not unlocked."
            )
            return

        try:
            plaintext_metadata = self._parse_json_object_text(
                self.credential_metadata_input,
                field_name="Metadata JSON (plaintext)",
                allow_empty=True,
            )
            plaintext_payload = self._parse_json_object_text(
                self.credential_payload_input,
                field_name="Payload JSON (plaintext)",
                allow_empty=False,
            )
        except ValueError as exc:
            self.status_label.setText(
                "Credential update failed.\n"
                f"Error: {exc}"
            )
            return

        next_version = current_version + 1

        try:
            encrypted = build_encrypted_item_finalize_payload(
                object_type="credential",
                object_id=credential_id,
                object_version=next_version,
                plaintext_metadata=plaintext_metadata,
                plaintext_payload=plaintext_payload,
                master_key_b64=master_key_b64,
            )
        except Exception as exc:
            self.status_label.setText(
                "Credential update failed.\n"
                f"Error: {exc}"
            )
            return

        self.credential_header_input.setPlainText(
            json.dumps(encrypted.encryption_header, indent=2)
        )

        result = self.desktop_service.update_credential(
            credential_id=credential_id,
            device_name=device_name,
            expected_current_version=current_version,
            encrypted_metadata=encrypted.encrypted_metadata,
            encrypted_payload=encrypted.encrypted_payload,
            encryption_header=encrypted.encryption_header,
        )

        if result.error is None and result.item is not None:
            decorated_item = dict(result.item)
            decorated_item["plaintext_metadata"] = plaintext_metadata
            decorated_item["plaintext_payload"] = plaintext_payload
            result = ObjectCreateResult(
                item=decorated_item,
                error=None,
                status_code=result.status_code,
            )

        self._render_credential_update_result(result)

    def run_update_note(self) -> None:
        device_name = self.device_name_input.text().strip()
        if not device_name:
            self.status_label.setText(
                "Note update failed.\n"
                "Error: Device name is empty."
            )
            return

        note_id = self.selected_note_id
        current_version = self.selected_note_current_version
        if not note_id or current_version is None:
            self.status_label.setText(
                "Note update failed.\n"
                "Error: Load a note detail first."
            )
            return

        master_key_b64 = self.desktop_service.current_session_vault_master_key()
        if not master_key_b64:
            self.status_label.setText(
                "Note update failed.\n"
                "Error: Session vault key is not unlocked."
            )
            return

        try:
            plaintext_metadata = self._parse_json_object_text(
                self.note_metadata_input,
                field_name="Metadata JSON (plaintext)",
                allow_empty=True,
            )
            plaintext_payload = self._parse_json_object_text(
                self.note_payload_input,
                field_name="Payload JSON (plaintext)",
                allow_empty=False,
            )
        except ValueError as exc:
            self.status_label.setText(
                "Note update failed.\n"
                f"Error: {exc}"
            )
            return

        next_version = current_version + 1

        try:
            encrypted = build_encrypted_item_finalize_payload(
                object_type="note",
                object_id=note_id,
                object_version=next_version,
                plaintext_metadata=plaintext_metadata,
                plaintext_payload=plaintext_payload,
                master_key_b64=master_key_b64,
            )
        except Exception as exc:
            self.status_label.setText(
                "Note update failed.\n"
                f"Error: {exc}"
            )
            return

        self.note_header_input.setPlainText(
            json.dumps(encrypted.encryption_header, indent=2)
        )

        result = self.desktop_service.update_note(
            note_id=note_id,
            device_name=device_name,
            expected_current_version=current_version,
            encrypted_metadata=encrypted.encrypted_metadata,
            encrypted_payload=encrypted.encrypted_payload,
            encryption_header=encrypted.encryption_header,
        )

        if result.error is None and result.item is not None:
            decorated_item = dict(result.item)
            decorated_item["plaintext_metadata"] = plaintext_metadata
            decorated_item["plaintext_payload"] = plaintext_payload
            result = ObjectCreateResult(
                item=decorated_item,
                error=None,
                status_code=result.status_code,
            )

        self._render_note_update_result(result)

    def run_delete_credential(self) -> None:
        credential_id = self.selected_credential_id
        if not credential_id:
            self.status_label.setText(
                "Credential delete failed.\n"
                "Error: Load a credential detail first."
            )
            return

        result = self.desktop_service.delete_credential(credential_id=credential_id)
        self._render_credential_delete_result(result)

    def run_delete_note(self) -> None:
        note_id = self.selected_note_id
        if not note_id:
            self.status_label.setText(
                "Note delete failed.\n"
                "Error: Load a note detail first."
            )
            return

        result = self.desktop_service.delete_note(note_id=note_id)
        self._render_note_delete_result(result)

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

    def run_unlock_vault_with_pin(self) -> None:
        if not self.desktop_service.is_authenticated():
            self.status_label.setText(
                "Vault PIN unlock failed.\n"
                "Error: No active session."
            )
            return

        pin_value = self.vault_pin_input.text().strip()
        if not pin_value:
            self.status_label.setText(
                "Vault PIN unlock failed.\n"
                "Error: PIN input is empty."
            )
            return

        try:
            self.desktop_service.unlock_session_vault_with_pin(pin_value)
        except ValueError as exc:
            self.status_label.setText(
                "Vault PIN unlock failed.\n"
                f"Error: {exc}"
            )
            self._refresh_action_states()
            return

        self.vault_pin_input.clear()
        self.status_label.setText(
            "Vault unlocked with PIN.\n"
            "Credentials, notes, and files can now use the shared session vault state."
        )
        self.refresh_session_label()
        self._refresh_after_vault_unlock()
        self._refresh_idle_policy()
        self._refresh_action_states()

    def run_enroll_vault_pin(self) -> None:
        if not self.desktop_service.is_authenticated():
            self.status_label.setText(
                "PIN enrollment failed.\n"
                "Error: No active session."
            )
            return

        if not self._is_vault_unlocked():
            self.status_label.setText(
                "PIN enrollment failed.\n"
                "Error: Unlock the vault with Advanced Recovery first."
            )
            return

        pin_value = self.vault_pin_input.text().strip()
        if not pin_value:
            self.status_label.setText(
                "PIN enrollment failed.\n"
                "Error: PIN input is empty."
            )
            return

        prior_status = self.desktop_service.local_pin_bootstrap_status()

        try:
            self.desktop_service.enroll_local_pin_bootstrap(pin=pin_value)
        except ValueError as exc:
            self.status_label.setText(
                "PIN enrollment failed.\n"
                f"Error: {exc}"
            )
            return

        self.vault_pin_input.clear()
        if prior_status == "current_account":
            self.status_label.setText(
                "PIN changed for this device.\n"
                "Future vault unlocks will use the updated PIN."
            )
        elif prior_status == "other_account":
            self.status_label.setText(
                "Device PIN replaced for the current account.\n"
                "Future vault unlocks on this desktop now belong to this account."
            )
        else:
            self.status_label.setText(
                "PIN saved for this device.\n"
                "Future vault unlocks can use PIN on this desktop."
            )
        self._refresh_action_states()

    def run_remove_vault_pin(self) -> None:
        if not self.desktop_service.is_authenticated():
            self.status_label.setText(
                "Remove PIN failed.\n"
                "Error: No active session."
            )
            return

        prior_status = self.desktop_service.local_pin_bootstrap_status()
        identifier_hint = self.desktop_service.local_pin_bootstrap_identifier_hint()

        if prior_status == "none":
            self.status_label.setText(
                "Remove PIN failed.\n"
                "Error: No local PIN is enrolled for this device."
            )
            self._refresh_action_states()
            return

        self.desktop_service.clear_local_pin_bootstrap()
        self.vault_pin_input.clear()
        if prior_status == "other_account" and identifier_hint:
            self.status_label.setText(
                "Local PIN removed from this device.\n"
                f"The removed enrollment previously belonged to: {identifier_hint}"
            )
        else:
            self.status_label.setText(
                "Local PIN removed from this device.\n"
                "Advanced Recovery remains available for fallback unlock."
            )
        self._refresh_action_states()

    def run_lock_vault_now(self) -> None:
        self.run_clear_session_key()

    def toggle_advanced_recovery(self) -> None:
        visible = not self.advanced_recovery_widget.isVisible()
        self.advanced_recovery_widget.setVisible(visible)
        self.toggle_advanced_recovery_button.setText(
            "Hide Advanced Recovery" if visible else "Show Advanced Recovery"
        )
        self._refresh_action_states()

    def run_unlock_session_key(self) -> None:
        if not self.desktop_service.is_authenticated():
            self.status_label.setText(
                "Session vault key unlock failed.\n"
                "Error: No active session."
            )
            return

        if self._is_file_job_running():
            self.status_label.setText(
                "A file job is still running.\n"
                "Wait for completion before changing the session key."
            )
            return

        master_key_b64 = self.file_master_key_b64_input.text().strip()
        if not master_key_b64:
            self.status_label.setText(
                "Session vault key unlock failed.\n"
                "Error: Session key input is empty."
            )
            return

        try:
            self.desktop_service.unlock_session_vault_with_recovery_key(master_key_b64)
        except ValueError as exc:
            self.status_label.setText(
                "Session vault key unlock failed.\n"
                f"Error: {exc}"
            )
            return

        self.file_master_key_b64_input.clear()
        self.status_label.setText(
            "Vault unlocked with recovery key.\n"
            "You can now enroll or replace a PIN on this device for everyday unlocks."
        )
        self.refresh_session_label()
        self._refresh_after_vault_unlock()
        self._refresh_idle_policy()

    def run_clear_session_key(self) -> None:
        if self._is_file_job_running():
            self.status_label.setText(
                "A file job is still running.\n"
                "Wait for completion before clearing the session key."
            )
            return

        if not self.desktop_service.is_authenticated():
            self.status_label.setText("No active session.")
            return

        self.desktop_service.clear_session_vault_master_key()
        self.file_master_key_b64_input.clear()
        self._clear_sensitive_views_for_locked_vault()
        self.status_label.setText(
            "Vault locked.\n"
            "The in-memory vault key was cleared and sensitive editors were wiped."
        )
        self.refresh_session_label()
        self._refresh_idle_policy()

    def run_create_file(self) -> None:
        if self._is_file_job_running():
            self.status_label.setText(
                "A file job is already running.\n"
                "Wait for completion before starting another one."
            )
            return

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

        master_key_b64 = self.desktop_service.current_session_vault_master_key()
        if not master_key_b64:
            self.status_label.setText(
                "File creation failed.\n"
                "Error: Session vault key is not unlocked."
            )
            return

        chunk_size_bytes = self.file_chunk_size_kib_input.value() * 1024

        thread = QThread(self)
        worker = FileUploadWorker(
            desktop_service=self.desktop_service,
            device_name=device_name,
            source_path=source_path,
            chunk_size_bytes=chunk_size_bytes,
            master_key_b64=master_key_b64,
        )
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.progress_text.connect(self._on_file_upload_progress_text)
        worker.progress_value.connect(self._on_file_upload_progress_value)
        worker.payload_preview_ready.connect(self._on_file_upload_payload_preview)
        worker.succeeded.connect(self._on_file_upload_success)
        worker.canceled.connect(self._on_file_upload_canceled)
        worker.failed.connect(self._on_file_upload_failure)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._on_file_upload_thread_finished)

        self.file_upload_thread = thread
        self.file_upload_worker = worker
        self.file_upload_progress.setValue(0)
        self._set_file_upload_busy(True)
        self.files_output.setPlainText(
            "Encrypted upload started in background.\n"
            "The window should remain responsive while the worker runs."
        )
        self.status_label.setText("Starting encrypted file upload...")
        thread.start()

    def run_cancel_file_upload(self) -> None:
        if not self._is_file_upload_running() or self.file_upload_worker is None:
            self.status_label.setText("No encrypted upload is running.")
            return

        self.cancel_file_upload_button.setEnabled(False)
        self.status_label.setText(
            "Cancellation requested.\n"
            "The upload will stop at the next safe checkpoint."
        )
        self.files_output.setPlainText(
            "Cancellation requested.\n"
            "Waiting for inspect/encrypt/finalize boundary."
        )
        self.file_upload_worker.request_cancel()

    def run_pick_download_target(self) -> None:
        current_target = self.file_download_target_input.text().strip()
        selected_item = self.files_list.currentItem()
        default_name = current_target
        if not default_name and selected_item is not None:
            selected_file_id = str(selected_item.data(Qt.ItemDataRole.UserRole) or "").strip()
            if selected_file_id:
                default_name = f"{selected_file_id}.bin"

        target_path, _ = QFileDialog.getSaveFileName(
            self,
            "Select Download Destination",
            default_name,
            "All files (*)",
        )
        if not target_path:
            return

        self.file_download_target_input.setText(target_path)
        self.status_label.setText(
            "Download target selected.\n"
            f"Path: {target_path}"
        )

    def run_download_file(self) -> None:
        if self._is_file_job_running():
            self.status_label.setText(
                "A file job is already running.\n"
                "Wait for completion before starting another one."
            )
            return

        item = self.files_list.currentItem()
        if item is None:
            self.status_label.setText("Select a file first.")
            return

        file_id = str(item.data(Qt.ItemDataRole.UserRole) or "").strip()
        if not file_id:
            self.status_label.setText("Selected file item has no file ID.")
            return

        target_path = self.file_download_target_input.text().strip()
        if not target_path:
            self.status_label.setText(
                "File download failed.\n"
                "Error: No local download target selected."
            )
            return

        master_key_b64 = self.desktop_service.current_session_vault_master_key()
        if not master_key_b64:
            self.status_label.setText(
                "File download failed.\n"
                "Error: Session vault key is not unlocked."
            )
            return

        thread = QThread(self)
        worker = FileDownloadWorker(
            desktop_service=self.desktop_service,
            file_id=file_id,
            target_path=target_path,
            master_key_b64=master_key_b64,
        )
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.progress_text.connect(self._on_file_download_progress_text)
        worker.progress_value.connect(self._on_file_download_progress_value)
        worker.succeeded.connect(self._on_file_download_success)
        worker.canceled.connect(self._on_file_download_canceled)
        worker.failed.connect(self._on_file_download_failure)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._on_file_download_thread_finished)

        self.file_download_thread = thread
        self.file_download_worker = worker
        self.file_download_progress.setValue(0)
        self._set_file_download_busy(True)
        self.files_output.setPlainText(
            "Encrypted file download started in background.\n"
            "The window should remain responsive while the worker runs."
        )
        self.status_label.setText("Starting encrypted file download...")
        thread.start()

    def run_cancel_file_download(self) -> None:
        if not self._is_file_download_running() or self.file_download_worker is None:
            self.status_label.setText("No encrypted download is running.")
            return

        self.cancel_file_download_button.setEnabled(False)
        self.status_label.setText(
            "Cancellation requested.\n"
            "The download will stop at the next safe checkpoint."
        )
        self.files_output.setPlainText(
            "Cancellation requested.\n"
            "Waiting for chunk/decrypt/write boundary."
        )
        self.file_download_worker.request_cancel()

    def reset_credential_create_fields(self) -> None:
        self.credential_metadata_input.setPlainText(
            json.dumps({"label": "Personal"}, indent=2)
        )
        self.credential_payload_input.setPlainText(
            json.dumps(
                {
                    "username": "alice",
                    "secret": "s3cr3t",
                    "url": "https://example.com",
                },
                indent=2,
            )
        )
        self.credential_header_input.clear()

    def reset_note_create_fields(self) -> None:
        self.note_type_input.setText("note")
        self.note_metadata_input.setPlainText(
            json.dumps({"tags": ["todo"]}, indent=2)
        )
        self.note_payload_input.setPlainText(
            json.dumps(
                {
                    "title": "todo",
                    "content": "buy milk",
                },
                indent=2,
            )
        )
        self.note_header_input.clear()

    def reset_file_create_fields(self) -> None:
        self.file_path_input.clear()
        self.file_download_target_input.clear()
        self.file_chunk_size_kib_input.setValue(8192)
        self.file_master_key_b64_input.clear()
        self.file_manifest_input.clear()
        self.file_header_input.clear()
        self.file_chunks_input.clear()
        self.file_upload_progress.setValue(0)
        self.file_download_progress.setValue(0)

    def load_credentials(self) -> None:
        result = self.desktop_service.fetch_credentials()
        self._render_credentials(result)

    def load_notes(self) -> None:
        result = self.desktop_service.fetch_notes()
        self._render_notes(result)

    def load_files(self) -> None:
        result = self.desktop_service.fetch_files()
        self._render_files(result)

    def _refresh_action_states(self) -> None:
        authenticated = self.desktop_service.is_authenticated()
        vault_unlocked = self._is_vault_unlocked()
        recovery_visible = self.advanced_recovery_widget.isVisible()
        pin_bootstrap_status = self.desktop_service.local_pin_bootstrap_status()
        pin_bootstrap_available = pin_bootstrap_status in {"current_account", "present", "other_account"}
        pin_text_present = bool(self.vault_pin_input.text().strip())
        identifier_hint = self.desktop_service.local_pin_bootstrap_identifier_hint()

        if not authenticated:
            self.pin_bootstrap_status_label.setText(
                "PIN unlock is available after login. No local PIN can be used while logged out."
            )
        elif pin_bootstrap_status == "current_account":
            self.pin_bootstrap_status_label.setText(
                "This device already has a local PIN enrollment for the current account. "
                "You can unlock with PIN, change it while unlocked, or remove it from this device."
            )
        elif pin_bootstrap_status == "other_account":
            hint_text = f" (hint: {identifier_hint})" if identifier_hint else ""
            self.pin_bootstrap_status_label.setText(
                "This device currently stores a local PIN enrollment for another account"
                f"{hint_text}. Unlock with Advanced Recovery to replace it for the current account, "
                "or remove the device PIN."
            )
        elif pin_bootstrap_status == "present":
            self.pin_bootstrap_status_label.setText(
                "A local PIN exists on this device, but no account is currently active."
            )
        else:
            self.pin_bootstrap_status_label.setText(
                "No local PIN is enrolled on this device for the current account yet. "
                "Unlock once with Advanced Recovery, then enroll a PIN for everyday use."
            )

        unlock_method = self.desktop_service.current_vault_unlock_method()
        if not authenticated:
            self.vault_unlock_source_label.setText(
                "Vault unlock source: none (logged out)."
            )
        elif not vault_unlocked:
            self.vault_unlock_source_label.setText(
                "Vault unlock source: vault is currently locked."
            )
        elif unlock_method == "pin":
            self.vault_unlock_source_label.setText(
                "Vault unlock source: PIN on this device."
            )
        elif unlock_method == "recovery_key":
            self.vault_unlock_source_label.setText(
                "Vault unlock source: Advanced Recovery key."
            )
        else:
            self.vault_unlock_source_label.setText(
                "Vault unlock source: session vault key is present."
            )

        self.vault_pin_input.setEnabled(authenticated)
        self.unlock_vault_pin_button.setEnabled(
            authenticated
            and not vault_unlocked
            and pin_bootstrap_status == "current_account"
            and pin_text_present
        )
        self.enroll_vault_pin_button.setEnabled(
            authenticated
            and vault_unlocked
            and pin_text_present
        )
        if pin_bootstrap_status == "current_account":
            self.enroll_vault_pin_button.setText("Change PIN on This Device")
        elif pin_bootstrap_status == "other_account":
            self.enroll_vault_pin_button.setText("Replace PIN for Current Account")
        else:
            self.enroll_vault_pin_button.setText("Enroll PIN on This Device")

        self.remove_vault_pin_button.setEnabled(authenticated and pin_bootstrap_available)
        self.lock_now_button.setEnabled(authenticated and vault_unlocked)
        self.toggle_advanced_recovery_button.setEnabled(authenticated)
        self.file_master_key_b64_input.setEnabled(
            authenticated and not vault_unlocked and recovery_visible
        )
        self.unlock_session_key_button.setEnabled(
            authenticated and not vault_unlocked and recovery_visible
        )
        self.clear_session_key_button.setEnabled(vault_unlocked)

        credential_item_selected = self.credentials_list.currentItem() is not None
        credential_detail_loaded = (
            self.selected_credential_id is not None
            and self.selected_credential_current_version is not None
        )
        self.load_credential_detail_button.setEnabled(credential_item_selected)
        self.create_credential_button.setEnabled(vault_unlocked)
        self.update_credential_button.setEnabled(vault_unlocked and credential_detail_loaded)
        self.delete_credential_button.setEnabled(vault_unlocked and credential_detail_loaded)

        note_item_selected = self.notes_list.currentItem() is not None
        note_detail_loaded = (
            self.selected_note_id is not None
            and self.selected_note_current_version is not None
        )
        self.load_note_detail_button.setEnabled(note_item_selected)
        self.create_note_button.setEnabled(vault_unlocked)
        self.update_note_button.setEnabled(vault_unlocked and note_detail_loaded)
        self.delete_note_button.setEnabled(vault_unlocked and note_detail_loaded)

        file_jobs_idle = not self._is_file_job_running()
        file_item_selected = self.files_list.currentItem() is not None
        file_source_ready = bool(self.file_path_input.text().strip())
        file_target_ready = bool(self.file_download_target_input.text().strip())

        self.load_file_detail_button.setEnabled(file_jobs_idle and file_item_selected)
        self.create_file_button.setEnabled(file_jobs_idle and vault_unlocked and file_source_ready)
        self.download_file_button.setEnabled(
            file_jobs_idle and vault_unlocked and file_item_selected and file_target_ready
        )

    def _is_vault_unlocked(self) -> bool:
        return self.desktop_service.has_session_vault_master_key()

    def _locked_detail_text(self, kind: str, item: dict) -> str:
        object_id = item.get("credential_id") or item.get("note_id") or item.get("file_id") or "-"
        lines = [
            f"{kind} detail is locked.",
            "Unlock Vault to view decrypted content.",
            "",
            f"ID: {object_id}",
            f"State: {item.get('state', '-')}",
            f"Current version: {item.get('current_version', '-')}",
        ]
        note_type = item.get("note_type")
        if note_type:
            lines.append(f"Type: {note_type}")
        return "\n".join(lines)

    def _clear_sensitive_views_for_locked_vault(self) -> None:
        self.reset_credential_create_fields()
        self.reset_note_create_fields()
        self.file_manifest_input.clear()
        self.file_header_input.clear()
        self.file_chunks_input.clear()

        if self.selected_credential_id:
            self.credentials_output.setPlainText(
                self._locked_detail_text(
                    "Credential",
                    {
                        "credential_id": self.selected_credential_id,
                        "current_version": self.selected_credential_current_version or "-",
                    },
                )
            )

        if self.selected_note_id:
            self.notes_output.setPlainText(
                self._locked_detail_text(
                    "Note",
                    {
                        "note_id": self.selected_note_id,
                        "current_version": self.selected_note_current_version or "-",
                    },
                )
            )

        self._refresh_action_states()

    def _refresh_after_vault_unlock(self) -> None:
        self._refresh_action_states()
        if self.selected_credential_id:
            self.load_credential_detail()
        if self.selected_note_id:
            self.load_note_detail()

    def _read_timeout_ms(
        self,
        env_name: str,
        *,
        default_seconds: int,
        minimum_seconds: int,
    ) -> int:
        raw = os.getenv(env_name, "").strip()
        if not raw:
            return default_seconds * 1000
        try:
            value = int(raw)
        except ValueError:
            return default_seconds * 1000
        if value < minimum_seconds:
            value = minimum_seconds
        return value * 1000

    def _stop_idle_timers(self) -> None:
        self.vault_auto_lock_timer.stop()
        self.session_auto_logout_timer.stop()

    def _refresh_idle_policy(self) -> None:
        if not self.desktop_service.is_authenticated():
            self._stop_idle_timers()
            return

        self.session_auto_logout_timer.start(self.session_auto_logout_timeout_ms)

        if self._is_vault_unlocked():
            self.vault_auto_lock_timer.start(self.vault_auto_lock_timeout_ms)
        else:
            self.vault_auto_lock_timer.stop()

    def _handle_user_activity(self) -> None:
        if not self.desktop_service.is_authenticated():
            return
        self._refresh_idle_policy()

    def _handle_vault_auto_lock_timeout(self) -> None:
        if not self.desktop_service.is_authenticated():
            return
        if not self._is_vault_unlocked():
            return
        if self._is_file_job_running():
            self.vault_auto_lock_timer.start(15000)
            self.status_label.setText(
                "Vault auto-lock delayed because a file job is still running."
            )
            return

        self.desktop_service.clear_session_vault_master_key()
        self.file_master_key_b64_input.clear()
        self._clear_sensitive_views_for_locked_vault()
        self.refresh_session_label()
        self.status_label.setText(
            "Vault auto-locked after inactivity.\n"
            "Sensitive editors were wiped from memory."
        )
        self._refresh_idle_policy()

    def _perform_local_logout(self, status_text: str) -> None:
        self.desktop_service.logout()
        self.reset_credential_create_fields()
        self.reset_note_create_fields()
        self.file_manifest_input.clear()
        self.file_header_input.clear()
        self.file_chunks_input.clear()
        self.credentials_list.clear()
        self.notes_list.clear()
        self.files_list.clear()
        self.credentials_output.clear()
        self.notes_output.clear()
        self.files_output.clear()
        self.file_master_key_b64_input.clear()
        self.selected_credential_id = None
        self.selected_credential_current_version = None
        self.selected_note_id = None
        self.selected_note_current_version = None
        self._stop_idle_timers()
        self.refresh_session_label()
        self._refresh_action_states()
        self.status_label.setText(status_text)
        self._save_ui_preferences()

    def _handle_session_auto_logout_timeout(self) -> None:
        if not self.desktop_service.is_authenticated():
            return
        if self._is_file_job_running():
            self.session_auto_logout_timer.start(30000)
            self.status_label.setText(
                "Session auto-logout delayed because a file job is still running."
            )
            return
        self._perform_local_logout("Session expired after inactivity.")

    def eventFilter(self, watched, event):  # type: ignore[override]
        if event is not None and event.type() in {
            QEvent.Type.MouseButtonPress,
            QEvent.Type.MouseButtonRelease,
            QEvent.Type.KeyPress,
            QEvent.Type.Wheel,
            QEvent.Type.FocusIn,
        }:
            self._handle_user_activity()
        return super().eventFilter(watched, event)

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
            self._refresh_action_states()
            return

        self.credentials_list.clear()
        for entry in result.items:
            widget_item = QListWidgetItem(credential_list_label(entry))
            widget_item.setData(Qt.ItemDataRole.UserRole, entry.get("credential_id"))
            self.credentials_list.addItem(widget_item)

        self.credentials_output.setPlainText(format_credentials_items(result.items))

        if self.credentials_list.count() > 0:
            self.credentials_list.setCurrentRow(0)

        self._refresh_action_states()

    def _render_notes(self, result: ObjectListResult) -> None:
        if result.error:
            self.notes_output.setPlainText(
                f"Notes fetch failed.\nError: {result.error}"
            )
            self._refresh_action_states()
            return

        self.notes_list.clear()
        for entry in result.items:
            widget_item = QListWidgetItem(note_list_label(entry))
            widget_item.setData(Qt.ItemDataRole.UserRole, entry.get("note_id"))
            self.notes_list.addItem(widget_item)

        self.notes_output.setPlainText(format_notes_items(result.items))

        if self.notes_list.count() > 0:
            self.notes_list.setCurrentRow(0)

        self._refresh_action_states()

    def _render_files(self, result: ObjectListResult) -> None:
        if result.error:
            self.files_output.setPlainText(
                f"Files fetch failed.\nError: {result.error}"
            )
            self._refresh_action_states()
            return

        self.files_list.clear()
        for entry in result.items:
            widget_item = QListWidgetItem(file_list_label(entry))
            widget_item.setData(Qt.ItemDataRole.UserRole, entry.get("file_id"))
            self.files_list.addItem(widget_item)

        self.files_output.setPlainText(format_files_items(result.items))

        if self.files_list.count() > 0:
            self.files_list.setCurrentRow(0)

        self._refresh_action_states()

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
        display_item = self._decorate_item_detail_for_local_display(item)

        list_result = self.desktop_service.fetch_credentials()
        self._render_credentials(list_result)

        if credential_id and not list_result.error:
            self._select_credential_item_by_id(credential_id)

        self._bind_credential_item_to_editors(display_item)
        self.credentials_output.setPlainText(format_credential_detail(display_item))
        self.tabs.setCurrentIndex(0)

        status_lines = [
            "Credential created.",
            f"Credential ID: {credential_id or '<unknown>'}",
        ]
        if list_result.error:
            status_lines.append(f"List refresh warning: {list_result.error}")

        self.status_label.setText("\n".join(status_lines))
        self._refresh_action_states()
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
        display_item = self._decorate_item_detail_for_local_display(item)

        list_result = self.desktop_service.fetch_notes()
        self._render_notes(list_result)

        if note_id and not list_result.error:
            self._select_note_item_by_id(note_id)

        self._bind_note_item_to_editors(display_item)
        self.notes_output.setPlainText(format_note_detail(display_item))
        self.tabs.setCurrentIndex(1)

        status_lines = [
            "Note created.",
            f"Note ID: {note_id or '<unknown>'}",
        ]
        if list_result.error:
            status_lines.append(f"List refresh warning: {list_result.error}")

        self.status_label.setText("\n".join(status_lines))
        self._refresh_action_states()
        self._save_ui_preferences()

    def _render_credential_delete_result(self, result: ObjectCreateResult) -> None:
        if result.error:
            self.credentials_output.setPlainText(
                f"Credential delete failed.\nError: {result.error}"
            )
            self.status_label.setText(
                "Credential delete failed.\n"
                f"Error: {result.error}"
            )
            return

        item = result.item or {}
        credential_id = str(item.get("credential_id", ""))

        list_result = self.desktop_service.fetch_credentials()
        self._render_credentials(list_result)

        self.selected_credential_id = None
        self.selected_credential_current_version = None
        self.reset_credential_create_fields()
        self.tabs.setCurrentIndex(0)

        status_lines = [
            "Credential deleted.",
            f"Credential ID: {credential_id or '<unknown>'}",
        ]
        if list_result.error:
            status_lines.append(f"List refresh warning: {list_result.error}")

        self.status_label.setText("\n".join(status_lines))
        self._refresh_action_states()
        self._save_ui_preferences()

    def _render_note_delete_result(self, result: ObjectCreateResult) -> None:
        if result.error:
            self.notes_output.setPlainText(
                f"Note delete failed.\nError: {result.error}"
            )
            self.status_label.setText(
                "Note delete failed.\n"
                f"Error: {result.error}"
            )
            return

        item = result.item or {}
        note_id = str(item.get("note_id", ""))

        list_result = self.desktop_service.fetch_notes()
        self._render_notes(list_result)

        self.selected_note_id = None
        self.selected_note_current_version = None
        self.reset_note_create_fields()
        self.tabs.setCurrentIndex(1)

        status_lines = [
            "Note deleted.",
            f"Note ID: {note_id or '<unknown>'}",
        ]
        if list_result.error:
            status_lines.append(f"List refresh warning: {list_result.error}")

        self.status_label.setText("\n".join(status_lines))
        self._refresh_action_states()
        self._save_ui_preferences()

    def _render_credential_update_result(self, result: ObjectCreateResult) -> None:
        if result.error:
            self.credentials_output.setPlainText(
                f"Credential update failed.\nError: {result.error}"
            )
            self.status_label.setText(
                "Credential update failed.\n"
                f"Error: {result.error}"
            )
            return

        item = result.item or {}
        credential_id = str(item.get("credential_id", ""))
        display_item = self._decorate_item_detail_for_local_display(item)

        list_result = self.desktop_service.fetch_credentials()
        self._render_credentials(list_result)

        if credential_id and not list_result.error:
            self._select_credential_item_by_id(credential_id)

        self._bind_credential_item_to_editors(display_item)
        self.credentials_output.setPlainText(format_credential_detail(display_item))
        self.tabs.setCurrentIndex(0)

        status_lines = [
            "Credential updated.",
            f"Credential ID: {credential_id or '<unknown>'}",
            f"Current version: {display_item.get('current_version', '<unknown>')}",
        ]
        if list_result.error:
            status_lines.append(f"List refresh warning: {list_result.error}")

        self.status_label.setText("\n".join(status_lines))
        self._refresh_action_states()
        self._save_ui_preferences()

    def _render_note_update_result(self, result: ObjectCreateResult) -> None:
        if result.error:
            self.notes_output.setPlainText(
                f"Note update failed.\nError: {result.error}"
            )
            self.status_label.setText(
                "Note update failed.\n"
                f"Error: {result.error}"
            )
            return

        item = result.item or {}
        note_id = str(item.get("note_id", ""))
        display_item = self._decorate_item_detail_for_local_display(item)

        list_result = self.desktop_service.fetch_notes()
        self._render_notes(list_result)

        if note_id and not list_result.error:
            self._select_note_item_by_id(note_id)

        self._bind_note_item_to_editors(display_item)
        self.notes_output.setPlainText(format_note_detail(display_item))
        self.tabs.setCurrentIndex(1)

        status_lines = [
            "Note updated.",
            f"Note ID: {note_id or '<unknown>'}",
            f"Current version: {display_item.get('current_version', '<unknown>')}",
        ]
        if list_result.error:
            status_lines.append(f"List refresh warning: {list_result.error}")

        self.status_label.setText("\n".join(status_lines))
        self._refresh_action_states()
        self._save_ui_preferences()

    def _is_file_upload_running(self) -> bool:
        return self.file_upload_thread is not None and self.file_upload_thread.isRunning()

    def _is_file_download_running(self) -> bool:
        return self.file_download_thread is not None and self.file_download_thread.isRunning()

    def _is_file_job_running(self) -> bool:
        return self._is_file_upload_running() or self._is_file_download_running()

    def _set_file_job_busy(self, *, upload_busy: bool, download_busy: bool) -> None:
        widgets = [
            self.probe_button,
            self.login_button,
            self.logout_button,
            self.close_button,
            self.load_credentials_button,
            self.load_notes_button,
            self.load_files_button,
            self.load_all_button,
            self.identifier_input,
            self.password_input,
            self.device_name_input,
            self.platform_input,
            self.pick_file_button,
            self.create_file_button,
            self.pick_download_target_button,
            self.download_file_button,
            self.reset_file_payload_button,
            self.load_file_detail_button,
            self.file_chunk_size_kib_input,
            self.file_master_key_b64_input,
            self.unlock_session_key_button,
            self.clear_session_key_button,
        ]
        for widget in widgets:
            widget.setEnabled(not (upload_busy or download_busy))

        self.cancel_file_upload_button.setEnabled(upload_busy)
        self.cancel_file_download_button.setEnabled(download_busy)

        self.tabs.setTabEnabled(0, not (upload_busy or download_busy))
        self.tabs.setTabEnabled(1, not (upload_busy or download_busy))
        self.tabs.setTabEnabled(2, True)
        self._refresh_action_states()

    def _set_file_upload_busy(self, is_busy: bool) -> None:
        self._set_file_job_busy(upload_busy=is_busy, download_busy=False)

    def _set_file_download_busy(self, is_busy: bool) -> None:
        self._set_file_job_busy(upload_busy=False, download_busy=is_busy)

    def _on_file_upload_progress_text(self, message: str) -> None:
        self.status_label.setText(message)

    def _on_file_upload_progress_value(self, value: int) -> None:
        self.file_upload_progress.setValue(max(0, min(100, value)))

    def _on_file_upload_payload_preview(
        self,
        encrypted_manifest: object,
        encryption_header: object,
        chunk_preview: object,
    ) -> None:
        self._render_generated_file_payload_preview(
            encrypted_manifest=encrypted_manifest,
            encryption_header=encryption_header,
            chunk_preview=chunk_preview,
        )

    def _on_file_upload_success(self, item: object) -> None:
        result_item = item if isinstance(item, dict) else {}
        self.file_upload_progress.setValue(100)
        self._render_file_create_result(
            ObjectCreateResult(
                item=result_item,
                error=None,
                status_code=201,
            )
        )

    def _on_file_upload_failure(self, error: str) -> None:
        self.files_output.setPlainText(
            f"File create failed.\nError: {error}"
        )
        self.status_label.setText(
            "File creation failed.\n"
            f"Error: {error}"
        )

    def _on_file_upload_canceled(self, message: str) -> None:
        self.files_output.setPlainText(
            f"File upload canceled.\nReason: {message}"
        )
        self.status_label.setText(
            "File upload canceled.\n"
            f"Reason: {message}"
        )

    def _on_file_upload_thread_finished(self) -> None:
        self._set_file_upload_busy(False)
        self.file_upload_worker = None
        self.file_upload_thread = None
        if self.file_upload_progress.value() < 100:
            self.file_upload_progress.setValue(0)

    def _on_file_download_progress_text(self, message: str) -> None:
        self.status_label.setText(message)

    def _on_file_download_progress_value(self, value: int) -> None:
        self.file_download_progress.setValue(max(0, min(100, value)))

    def _on_file_download_success(self, item: object) -> None:
        result_item = item if isinstance(item, dict) else {}
        self.file_download_progress.setValue(100)
        self.files_output.setPlainText(
            "\n".join(
                [
                    "File downloaded.",
                    f"File ID: {result_item.get('file_id', '<unknown>')}",
                    f"Saved to: {result_item.get('target_path', '<unknown>')}",
                    f"Bytes written: {result_item.get('bytes_written', '<unknown>')}",
                    f"Chunk count: {result_item.get('chunk_count', '<unknown>')}",
                ]
            )
        )
        self.status_label.setText(
            "File download completed.\n"
            f"Saved to: {result_item.get('target_path', '<unknown>')}"
        )
        self.tabs.setCurrentIndex(2)
        self._save_ui_preferences()

    def _on_file_download_failure(self, error: str) -> None:
        self.files_output.setPlainText(
            f"File download failed.\nError: {error}"
        )
        self.status_label.setText(
            "File download failed.\n"
            f"Error: {error}"
        )

    def _on_file_download_canceled(self, message: str) -> None:
        self.files_output.setPlainText(
            f"File download canceled.\nReason: {message}"
        )
        self.status_label.setText(
            "File download canceled.\n"
            f"Reason: {message}"
        )

    def _on_file_download_thread_finished(self) -> None:
        self._set_file_download_busy(False)
        self.file_download_worker = None
        self.file_download_thread = None
        if self.file_download_progress.value() < 100:
            self.file_download_progress.setValue(0)

    def _render_generated_file_payload_preview(
        self,
        *,
        encrypted_manifest: object,
        encryption_header: object,
        chunk_preview: object,
    ) -> None:
        self.file_manifest_input.setPlainText(
            json.dumps(encrypted_manifest, indent=2)
        )
        self.file_header_input.setPlainText(
            json.dumps(encryption_header, indent=2)
        )
        self.file_chunks_input.setPlainText(
            json.dumps(chunk_preview, indent=2)
        )

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
            self.selected_credential_id = None
            self.selected_credential_current_version = None
            self.credentials_output.setPlainText(
                f"Credential detail fetch failed.\nError: {result.error}"
            )
            self._refresh_action_states()
            return

        item = result.item or {}
        if not self._is_vault_unlocked():
            self._bind_credential_item_to_editors({})
            self.selected_credential_id = str(item.get("credential_id", "")).strip() or None
            try:
                current_version = int(item.get("current_version"))
            except (TypeError, ValueError):
                current_version = None
            self.selected_credential_current_version = (
                current_version if current_version is not None and current_version >= 1 else None
            )
            self.credentials_output.setPlainText(self._locked_detail_text("Credential", item))
            self._refresh_action_states()
            return

        display_item = self._decorate_item_detail_for_local_display(item)
        self._bind_credential_item_to_editors(display_item)
        self.credentials_output.setPlainText(format_credential_detail(display_item))
        self._refresh_action_states()

    def _render_note_detail(self, result: ObjectDetailResult) -> None:
        if result.error:
            self.selected_note_id = None
            self.selected_note_current_version = None
            self.notes_output.setPlainText(
                f"Note detail fetch failed.\nError: {result.error}"
            )
            self._refresh_action_states()
            return

        item = result.item or {}
        if not self._is_vault_unlocked():
            self._bind_note_item_to_editors({})
            self.selected_note_id = str(item.get("note_id", "")).strip() or None
            try:
                current_version = int(item.get("current_version"))
            except (TypeError, ValueError):
                current_version = None
            self.selected_note_current_version = (
                current_version if current_version is not None and current_version >= 1 else None
            )
            self.notes_output.setPlainText(self._locked_detail_text("Note", item))
            self._refresh_action_states()
            return

        display_item = self._decorate_item_detail_for_local_display(item)
        self._bind_note_item_to_editors(display_item)
        self.notes_output.setPlainText(format_note_detail(display_item))
        self._refresh_action_states()

    def _decorate_item_detail_for_local_display(self, item: dict) -> dict:
        display_item = dict(item)
        if not item:
            return display_item

        master_key_b64 = self.desktop_service.current_session_vault_master_key()
        if not master_key_b64:
            display_item["decryption_error"] = "Session vault key is not unlocked."
            return display_item

        try:
            decrypted = decrypt_item_detail(item=item, master_key_b64=master_key_b64)
        except Exception as exc:
            display_item["decryption_error"] = str(exc)
            return display_item

        display_item["plaintext_metadata"] = decrypted.plaintext_metadata
        display_item["plaintext_payload"] = decrypted.plaintext_payload
        return display_item

    def _bind_credential_item_to_editors(self, item: dict) -> None:
        credential_id = str(item.get("credential_id", "")).strip()
        self.selected_credential_id = credential_id or None

        try:
            current_version = int(item.get("current_version"))
        except (TypeError, ValueError):
            current_version = None
        self.selected_credential_current_version = (
            current_version if current_version is not None and current_version >= 1 else None
        )

        plaintext_payload = item.get("plaintext_payload")
        plaintext_metadata = item.get("plaintext_metadata")

        if not isinstance(plaintext_payload, dict):
            self.credential_metadata_input.clear()
            self.credential_payload_input.clear()
            self.credential_header_input.clear()
            return

        if isinstance(plaintext_metadata, dict):
            self.credential_metadata_input.setPlainText(
                json.dumps(plaintext_metadata, indent=2)
            )
        else:
            self.credential_metadata_input.clear()

        self.credential_payload_input.setPlainText(
            json.dumps(plaintext_payload, indent=2)
        )
        self.credential_header_input.clear()

    def _bind_note_item_to_editors(self, item: dict) -> None:
        note_id = str(item.get("note_id", "")).strip()
        self.selected_note_id = note_id or None

        try:
            current_version = int(item.get("current_version"))
        except (TypeError, ValueError):
            current_version = None
        self.selected_note_current_version = (
            current_version if current_version is not None and current_version >= 1 else None
        )

        note_type = str(item.get("note_type", "")).strip() or "note"
        self.note_type_input.setText(note_type)

        plaintext_payload = item.get("plaintext_payload")
        plaintext_metadata = item.get("plaintext_metadata")

        if not isinstance(plaintext_payload, dict):
            self.note_metadata_input.clear()
            self.note_payload_input.clear()
            self.note_header_input.clear()
            return

        if isinstance(plaintext_metadata, dict):
            self.note_metadata_input.setPlainText(
                json.dumps(plaintext_metadata, indent=2)
            )
        else:
            self.note_metadata_input.clear()

        self.note_payload_input.setPlainText(
            json.dumps(plaintext_payload, indent=2)
        )
        self.note_header_input.clear()

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
            f"Session ID: {session.session_id}\n"
            f"Vault key: {'loaded' if self.desktop_service.has_session_vault_master_key() else 'not loaded'}"
        )
