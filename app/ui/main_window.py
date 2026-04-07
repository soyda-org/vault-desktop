from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import re
import secrets

from PySide6.QtCore import QByteArray, QThread, Qt, QEvent, QTimer
from PySide6.QtGui import QColor, QFont, QFontDatabase, QTextDocument

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QProgressBar,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QSizePolicy,
)

from app.core.config import DesktopSettings
from app.core.local_settings import (
    LocalSettingsStore,
    PersistedUiSettings,
    detect_local_device_defaults,
)
from app.core.pin_bootstrap import MIN_PIN_LENGTH, validate_pin
from app.core.session import DesktopSession
from app.services.api_client import (
    ObjectCreateResult,
    ObjectDetailResult,
    ObjectListResult,
    VaultApiClient,
)
from app.services.desktop_service import VaultDesktopService
from app.ui.signup_dialog import SignupDialog
from app.ui.network_action_worker import NetworkActionWorker
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
from app.services.quick_text_crypto import (
    QuickTextCryptoError,
    available_method_labels,
    decrypt_text,
    encrypt_text,
    method_summary_for_key,
    passphrase_mode_for_method,
)
from app.services.vault_gateway import AuthenticatedVaultGateway
from app.ui.file_download_worker import FileDownloadWorker
from app.ui.file_upload_worker import FileUploadWorker
from app.ui.item_editor_dialog import (
    CredentialItemEditorDialog,
    JsonItemEditorDialog,
    NoteItemEditorDialog,
)
from app.ui.surfaces import (
    GeneratorWorkspaceView,
    SystemWorkspaceView,
    VaultWorkspaceView,
)
from app.ui.dashboard_formatters import (
    credential_list_label,
    file_list_label,
    format_credentials_items,
    format_file_detail,
    format_files_items,
    format_notes_items,
    note_list_label,
)


class ActivityStatusLabel(QLabel):
    def __init__(self, on_change, text: str = "") -> None:
        super().__init__(text)
        self._on_change = on_change

    def setText(self, text: str) -> None:  # type: ignore[override]
        super().setText(text)
        self._on_change(text)


_MARKDOWN_PATTERN = re.compile(
    r"(^#{1,6}\s)|(^[-*+]\s)|(^\d+\.\s)|(```)|(`[^`]+`)|(\[[^\]]+\]\([^)]+\))|(\*\*[^*]+\*\*)|(^>\s)",
    re.MULTILINE,
)


def _markdown_preview_stylesheet(palette: dict[str, str]) -> str:
    return f"""
        body {{
            color: {palette["text"]};
        }}
        pre {{
            background-color: #0b1220;
            border: 1px solid {palette["border"]};
            border-radius: 10px;
            padding: 12px;
            color: {palette["text"]};
            white-space: pre-wrap;
            font-family: "Courier New";
        }}
        code {{
            background-color: {palette["surface_alt"]};
            border: 1px solid {palette["border"]};
            border-radius: 6px;
            padding: 2px 4px;
            color: #dbeafe;
            font-family: "Courier New";
        }}
    """


def _render_markdown_preview_html(text: str, palette: dict[str, str]) -> str:
    document = QTextDocument()
    document.setMarkdown(text or "")
    html = document.toHtml()
    style_block = f"<style>{_markdown_preview_stylesheet(palette)}</style>"
    if "<head>" in html:
        return html.replace("<head>", f"<head>{style_block}", 1)
    return f"{style_block}{html}"


def _theme_palette(theme: str) -> dict[str, str]:
    if theme == "dark":
        return {
            "window": "#101b31",
            "surface": "#0f172a",
            "panel": "#101b31",
            "surface_alt": "#111c2e",
            "input": "#162235",
            "border": "#243247",
            "text": "#e2e8f0",
            "muted": "#94a3b8",
            "primary": "#2563eb",
            "primary_hover": "#1d4ed8",
            "danger": "#ef4444",
            "danger_bg": "#2b1318",
            "success": "#22c55e",
            "warning": "#f59e0b",
            "info": "#38bdf8",
            "nav_bg": "#162235",
            "selection": "#1d4ed8",
            "badge_bg": "#15243a",
            "mono_bg": "#0b1322",
        }
    return {
        "window": "#f6f7fb",
        "surface": "#ffffff",
        "panel": "#f1f5fb",
        "surface_alt": "#f5f7fb",
        "input": "#fbfcfe",
        "border": "#d8e0ea",
        "text": "#0f172a",
        "muted": "#475569",
        "primary": "#2563eb",
        "primary_hover": "#1d4ed8",
        "danger": "#ef4444",
        "danger_bg": "#fff2f2",
        "success": "#16a34a",
        "warning": "#d97706",
        "info": "#0284c7",
        "nav_bg": "#f0f4f8",
        "selection": "#dbeafe",
        "badge_bg": "#eff4ff",
        "mono_bg": "#eef3f8",
    }


def _load_embedded_font_family() -> str:
    fonts_dir = Path(__file__).resolve().parents[1] / "assets" / "fonts"
    preferred_family = "Courier Code"
    for font_name in (
        "CourierCode-Roman.ttf",
        "CourierCode-Bold.ttf",
        "CourierCode-Italic.ttf",
        "CourierCode-BoldItalic.ttf",
    ):
        font_path = fonts_dir / font_name
        if not font_path.exists():
            continue
        font_id = QFontDatabase.addApplicationFont(str(font_path))
        if font_id == -1:
            continue
        families = QFontDatabase.applicationFontFamilies(font_id)
        if families:
            preferred_family = families[0]
    return preferred_family


class MainWindow(QMainWindow):
    _NAVBAR_LABELS = {
        "theme_light": "Light",
        "theme_dark": "Dark",
        "theme_light_compact": "L",
        "theme_dark_compact": "D",
        "generator": "Generator",
        "generator_compact": "G",
        "access": "Access",
        "access_compact": "A",
        "vault": "Vault",
        "vault_compact": "V",
    }
    _NOTE_ACTION_LABELS = {
        "create": ("New Note", "N"),
        "update": ("Edit Note", "E"),
        "delete": ("Delete Note", "D"),
    }

    def __init__(self, settings: DesktopSettings) -> None:
        super().__init__()
        self.settings = settings
        self.local_settings_store = LocalSettingsStore()
        self.persisted_ui_settings = self.local_settings_store.load()
        self._pending_window_position: tuple[int, int] | None = None

        self.api_client = VaultApiClient(self.persisted_ui_settings.api_base_url)
        self.desktop_service = VaultDesktopService(
            api_client=self.api_client,
            vault_gateway=AuthenticatedVaultGateway(self.api_client),
        )
        self._restore_persisted_session()
        self.current_theme = (
            self.persisted_ui_settings.theme
            if self.persisted_ui_settings.theme in {"light", "dark"}
            else "light"
        )
        self.ui_font_family = _load_embedded_font_family()

        self.setWindowTitle(settings.app_name)
        self.setMinimumSize(600, 400)
        self.resize(
            max(600, self.persisted_ui_settings.window_width),
            max(400, self.persisted_ui_settings.window_height),
        )
        if self.persisted_ui_settings.window_geometry_b64:
            self.restoreGeometry(
                QByteArray.fromBase64(
                    self.persisted_ui_settings.window_geometry_b64.encode("ascii")
                )
            )
        if (
            self.persisted_ui_settings.window_x is not None
            and self.persisted_ui_settings.window_y is not None
        ):
            self._pending_window_position = (
                self.persisted_ui_settings.window_x,
                self.persisted_ui_settings.window_y,
            )
            self.move(*self._pending_window_position)
        self._apply_theme()

        self._last_activity_message = ""
        self._last_probe_result = None

        self.status_label = ActivityStatusLabel(
            self._handle_status_text_change,
            "Press 'Probe API' or login.",
        )
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setObjectName("inlineStatusText")
        self.vault_access_status_label = QLabel(self.status_label.text())
        self.vault_access_status_label.setWordWrap(True)
        self.vault_access_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.vault_access_status_label.setObjectName("inlineStatusText")
        self.vault_access_status_label.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Minimum,
        )
        self.vault_access_status_label.setMinimumHeight(
            self.fontMetrics().lineSpacing() * 2 + 6
        )

        self.session_label = QLabel("No active session.")
        self.session_label.setWordWrap(True)
        self.session_label.setObjectName("sessionBody")

        self.connection_state_label = QLabel()
        self.connection_state_label.setObjectName("statePill")
        self.session_state_label = QLabel()
        self.session_state_label.setObjectName("statePill")
        self.vault_state_label = QLabel()
        self.vault_state_label.setObjectName("statePill")
        self.vault_access_connection_state_label = QLabel()
        self.vault_access_connection_state_label.setObjectName("statePill")
        self.vault_access_session_state_label = QLabel()
        self.vault_access_session_state_label.setObjectName("statePill")
        self.vault_access_vault_state_label = QLabel()
        self.vault_access_vault_state_label.setObjectName("statePill")
        self.api_details_label = QLabel()
        self.api_details_label.setObjectName("technicalMeta")
        self.api_details_label.setWordWrap(False)
        self.vault_access_api_details_label = QLabel()
        self.vault_access_api_details_label.setObjectName("technicalMeta")
        self.vault_access_api_details_label.setWordWrap(False)

        self.activity_log_list = QListWidget()
        self.activity_log_list.setObjectName("activityLog")
        self.activity_log_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        self.remember_session_checkbox = QCheckBox("Stay signed in on this device")
        self.remember_session_checkbox.setObjectName("rememberSessionCheckbox")
        self.remember_session_checkbox.setChecked(
            self.persisted_ui_settings.remember_session
        )
        self.remember_session_checkbox.toggled.connect(
            lambda *_: self._handle_remember_session_toggle()
        )
        self.keep_vault_open_checkbox = QCheckBox("Keep vault open on this device")
        self.keep_vault_open_checkbox.setObjectName("keepVaultOpenCheckbox")
        self.keep_vault_open_checkbox.setProperty("workspaceFooterText", True)
        self.keep_vault_open_checkbox.setChecked(
            self.persisted_ui_settings.keep_vault_open
        )
        self.keep_vault_open_checkbox.toggled.connect(
            lambda *_: self._handle_keep_vault_open_toggle()
        )
        self.vault_auto_lock_countdown_label = QLabel()
        self.vault_auto_lock_countdown_label.setObjectName("vaultAutoLockCountdown")
        self.vault_auto_lock_countdown_label.setProperty("workspaceFooterText", True)

        self.copy_activity_log_button = QPushButton("Copy Diagnostics")
        self.copy_activity_log_button.clicked.connect(self.run_copy_activity_log)
        self.clear_activity_log_button = QPushButton("Clear Log")
        self.clear_activity_log_button.clicked.connect(self.run_clear_activity_log)
        self.system_messages_back_button = QPushButton("Back")
        self.system_messages_back_button.clicked.connect(self._return_from_system_logs)

        self.identifier_input = QLineEdit()
        self.identifier_input.setText(self.persisted_ui_settings.identifier)
        self.identifier_input.setPlaceholderText("username")
        self.identifier_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.identifier_input.setProperty("ghostField", True)
        self.identifier_input.returnPressed.connect(self.run_login)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("........")
        self.password_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.password_input.setProperty("ghostField", True)
        self.password_input.returnPressed.connect(self.run_login)

        self.device_name_input = QLineEdit()
        self.device_name_input.setText(self.persisted_ui_settings.device_name)
        self.device_name_input.setPlaceholderText("device name - automatically filled")
        self.device_name_input.setToolTip("Automatically filled from this device.")
        self.device_name_input.setProperty("autoFilled", True)
        self.device_name_input.setProperty("ghostField", True)
        self.device_name_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.device_name_input.setReadOnly(True)
        self.device_name_input.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        self.platform_input = QLineEdit()
        self.platform_input.setText(self.persisted_ui_settings.platform)
        self.platform_input.setPlaceholderText("platform - automatically filled")
        self.platform_input.setToolTip("Automatically filled from this device.")
        self.platform_input.setProperty("autoFilled", True)
        self.platform_input.setProperty("ghostField", True)
        self.platform_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.platform_input.setReadOnly(True)
        self.platform_input.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        self.probe_button = QPushButton("Probe API")
        self.probe_button.setProperty("tone", "primary")
        self.probe_button.setProperty("hoverGlow", "light")
        self.probe_button.clicked.connect(self.run_probe)
        self.vault_access_probe_button = QPushButton("Probe API")
        self.vault_access_probe_button.setProperty("tone", "primary")
        self.vault_access_probe_button.setProperty("hoverGlow", "light")
        self.vault_access_probe_button.clicked.connect(self.run_probe)

        self.login_button = QPushButton("Login")
        self.login_button.setProperty("tone", "secondary")
        self.login_button.setProperty("hoverGlow", "light")
        self.login_button.clicked.connect(self.run_login)

        self.sign_up_button = QPushButton("Sign Up")
        self.sign_up_button.setProperty("tone", "secondary")
        self.sign_up_button.setProperty("hoverGlow", "light")
        self.sign_up_button.clicked.connect(self.run_open_signup_dialog)

        self.logout_button = QPushButton("Logout")
        self.logout_button.setProperty("tone", "danger")
        self.logout_button.clicked.connect(self.run_logout)
        self.vault_logout_button = QPushButton("Logout")
        self.vault_logout_button.setProperty("tone", "danger")
        self.vault_logout_button.clicked.connect(self.run_logout)

        self.close_button = QPushButton("Close App")
        self.close_button.setProperty("hoverGlow", "danger")
        self.close_button.clicked.connect(self.run_close)

        self.load_credentials_button = QPushButton("Load Credentials")
        self.load_credentials_button.clicked.connect(self.load_credentials)
        self.load_credentials_button.setProperty("tone", "secondary")

        self.load_notes_button = QPushButton("Load Notes")
        self.load_notes_button.clicked.connect(self.load_notes)
        self.load_notes_button.setProperty("tone", "secondary")

        self.load_files_button = QPushButton("Load Files")
        self.load_files_button.clicked.connect(self.load_files)
        self.load_files_button.setProperty("tone", "secondary")

        self.load_all_button = QPushButton("Load All")
        self.load_all_button.clicked.connect(self.load_all)
        self.load_all_button.setProperty("tone", "secondary")

        self.create_credential_button = QPushButton("New")
        self.create_credential_button.clicked.connect(self.run_open_create_credential_dialog)
        self.create_credential_button.setProperty("tone", "primary")

        self.update_credential_button = QPushButton("Edit")
        self.update_credential_button.clicked.connect(self.run_open_update_credential_dialog)
        self.update_credential_button.setEnabled(False)

        self.delete_credential_button = QPushButton("Delete")
        self.delete_credential_button.clicked.connect(self.run_delete_credential)
        self.delete_credential_button.setEnabled(False)
        self.delete_credential_button.setProperty("tone", "danger")

        self.reset_credential_payload_button = QPushButton("Reset Payload")
        self.reset_credential_payload_button.clicked.connect(self.reset_credential_create_fields)
        self.reset_credential_payload_button.setProperty("tone", "secondary")

        self.load_note_detail_button = QPushButton("Load Selected Note")
        self.load_note_detail_button.clicked.connect(self.load_note_detail)
        self.load_note_detail_button.setEnabled(False)
        self.load_note_detail_button.setProperty("tone", "secondary")

        self.create_note_button = QPushButton("New Note")
        self.create_note_button.clicked.connect(self.run_open_create_note_dialog)
        self.create_note_button.setProperty("tone", "primary")

        self.update_note_button = QPushButton("Edit Note")
        self.update_note_button.clicked.connect(self.run_open_update_note_dialog)
        self.update_note_button.setEnabled(False)

        self.delete_note_button = QPushButton("Delete Note")
        self.delete_note_button.clicked.connect(self.run_delete_note)
        self.delete_note_button.setEnabled(False)
        self.delete_note_button.setProperty("tone", "danger")

        self.reset_note_payload_button = QPushButton("Reset Payload")
        self.reset_note_payload_button.clicked.connect(self.reset_note_create_fields)
        self.reset_note_payload_button.setProperty("tone", "secondary")

        self.pick_file_button = QPushButton("Pick File")
        self.pick_file_button.clicked.connect(self.run_pick_file)
        self.pick_file_button.setProperty("tone", "secondary")

        self.create_file_button = QPushButton("Create File")
        self.create_file_button.clicked.connect(self.run_create_file)
        self.create_file_button.setEnabled(False)
        self.create_file_button.setProperty("tone", "primary")

        self.cancel_file_upload_button = QPushButton("Cancel Upload")
        self.cancel_file_upload_button.clicked.connect(self.run_cancel_file_upload)
        self.cancel_file_upload_button.setEnabled(False)
        self.cancel_file_upload_button.setProperty("tone", "danger")

        self.pick_download_target_button = QPushButton("Save Path")
        self.pick_download_target_button.clicked.connect(self.run_pick_download_target)
        self.pick_download_target_button.setProperty("tone", "secondary")

        self.download_file_button = QPushButton("Download File")
        self.download_file_button.clicked.connect(self.run_download_file)
        self.download_file_button.setEnabled(False)
        self.download_file_button.setProperty("tone", "primary")

        self.cancel_file_download_button = QPushButton("Cancel Download")
        self.cancel_file_download_button.clicked.connect(self.run_cancel_file_download)
        self.cancel_file_download_button.setEnabled(False)
        self.cancel_file_download_button.setProperty("tone", "danger")

        self.reset_file_payload_button = QPushButton("Reset Draft")
        self.reset_file_payload_button.clicked.connect(self.reset_file_create_fields)
        self.reset_file_payload_button.setProperty("tone", "secondary")

        self.file_upload_thread: QThread | None = None
        self.file_upload_worker: FileUploadWorker | None = None
        self.file_download_thread: QThread | None = None
        self.file_download_worker: FileDownloadWorker | None = None
        self._network_action_thread: QThread | None = None
        self._network_action_worker: NetworkActionWorker | None = None

        self.selected_credential_id: str | None = None
        self.selected_credential_current_version: int | None = None
        self._credential_items_cache: list[dict] = []
        self.current_credential_filter = "active"
        self.selected_note_id: str | None = None
        self.selected_note_current_version: int | None = None
        self._note_items_cache: list[dict] = []
        self.current_note_filter = "active"
        self._credential_detail_password_plaintext = ""

        self.credentials_list = QListWidget()
        self.credentials_list.currentItemChanged.connect(lambda *_: self.load_credential_detail())
        self.credentials_list.itemDoubleClicked.connect(lambda _: self.load_credential_detail())
        self.credentials_active_filter_button = QPushButton("Active")
        self.credentials_active_filter_button.setProperty("segment", "true")
        self.credentials_active_filter_button.clicked.connect(
            lambda: self._set_credential_filter("active")
        )
        self.credentials_deleted_filter_button = QPushButton("Deleted")
        self.credentials_deleted_filter_button.setProperty("segment", "true")
        self.credentials_deleted_filter_button.clicked.connect(
            lambda: self._set_credential_filter("deleted")
        )

        self.notes_list = QListWidget()
        self.notes_list.setMinimumWidth(0)
        self.notes_list.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Expanding,
        )
        self.notes_list.itemDoubleClicked.connect(lambda _: self.load_note_detail())
        self.notes_active_filter_button = QPushButton("Active")
        self.notes_active_filter_button.setProperty("segment", "true")
        self.notes_active_filter_button.clicked.connect(
            lambda: self._set_note_filter("active")
        )
        self.notes_deleted_filter_button = QPushButton("Deleted")
        self.notes_deleted_filter_button.setProperty("segment", "true")
        self.notes_deleted_filter_button.clicked.connect(
            lambda: self._set_note_filter("deleted")
        )

        self.files_list = QListWidget()
        self.files_list.itemDoubleClicked.connect(lambda _: self.load_file_detail())

        self.credentials_output = QTextEdit()
        self.credentials_output.setReadOnly(True)
        self.credentials_output.setPlaceholderText("Credential details will appear here.")

        self.credential_detail_stack = QStackedWidget()
        self.credential_detail_message = self.credentials_output

        self.credential_detail_name_input = QLineEdit()
        self.credential_detail_name_input.setReadOnly(True)
        self.credential_detail_name_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.credential_detail_name_input.setMinimumWidth(320)
        self.credential_detail_name_input.setMaximumWidth(420)
        self.credential_detail_name_input.setProperty("ghostField", True)
        self.credential_detail_name_input.setProperty("autoFilled", True)
        self.credential_detail_username_input = QLineEdit()
        self.credential_detail_username_input.setReadOnly(True)
        self.credential_detail_username_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.credential_detail_username_input.setMinimumWidth(140)
        self.credential_detail_username_input.setMaximumWidth(420)
        self.credential_detail_password_input = QLineEdit()
        self.credential_detail_password_input.setReadOnly(True)
        self.credential_detail_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.credential_detail_password_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.credential_detail_password_input.setMinimumWidth(140)
        self.credential_detail_password_input.setMaximumWidth(420)
        self.credential_detail_url_input = QLineEdit()
        self.credential_detail_url_input.setReadOnly(True)
        self.credential_detail_url_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.credential_detail_url_input.setMinimumWidth(320)
        self.credential_detail_url_input.setMaximumWidth(420)
        self.credential_detail_url_input.setProperty("ghostField", True)
        self.credential_detail_url_input.setProperty("autoFilled", True)
        self.credential_detail_state_input = QLineEdit()
        self.credential_detail_state_input.setReadOnly(True)

        self.copy_credential_name_button = QPushButton("Copy")
        self.copy_credential_name_button.setProperty("tone", "secondary")
        self.copy_credential_name_button.setProperty("hoverGlow", "light")
        self.copy_credential_name_button.clicked.connect(
            lambda: self._copy_text_value(
                self.credential_detail_name_input.text(),
                "Credential name copied to clipboard.",
            )
        )
        self.copy_credential_username_button = QPushButton("Copy")
        self.copy_credential_username_button.setProperty("tone", "secondary")
        self.copy_credential_username_button.setProperty("hoverGlow", "light")
        self.copy_credential_username_button.clicked.connect(
            lambda: self._copy_text_value(
                self.credential_detail_username_input.text(),
                "Credential username copied to clipboard.",
            )
        )
        self.copy_credential_password_button = QPushButton("Copy")
        self.copy_credential_password_button.setProperty("tone", "secondary")
        self.copy_credential_password_button.setProperty("hoverGlow", "light")
        self.copy_credential_password_button.clicked.connect(
            lambda: self._copy_text_value(
                self._credential_detail_password_plaintext,
                "Credential password copied to clipboard.",
            )
        )
        self.toggle_credential_password_button = QPushButton("Show")
        self.toggle_credential_password_button.setProperty("tone", "secondary")
        self.toggle_credential_password_button.setProperty("hoverGlow", "light")
        self.toggle_credential_password_button.clicked.connect(
            self._toggle_credential_password_visibility
        )
        self.copy_credential_url_button = QPushButton("Copy")
        self.copy_credential_url_button.setProperty("tone", "secondary")
        self.copy_credential_url_button.setProperty("hoverGlow", "light")
        self.copy_credential_url_button.clicked.connect(
            lambda: self._copy_text_value(
                self.credential_detail_url_input.text(),
                "Credential URL copied to clipboard.",
            )
        )
        credential_detail_outline = QFrame()
        credential_detail_outline.setObjectName("credentialDetailOutline")
        credential_detail_outline.setSizePolicy(
            QSizePolicy.Policy.Maximum,
            QSizePolicy.Policy.Maximum,
        )
        credential_detail_fields_layout = QVBoxLayout(credential_detail_outline)
        credential_detail_fields_layout.setContentsMargins(4, 4, 4, 4)
        credential_detail_fields_layout.setSpacing(10)
        credential_detail_fields_layout.addLayout(
            self._build_readonly_detail_row(
                None,
                self.credential_detail_name_input,
                centered=True,
            )
        )
        credential_detail_fields_layout.addLayout(
            self._build_readonly_detail_row(
                None,
                self.credential_detail_username_input,
                self.copy_credential_username_button,
                centered=True,
            )
        )
        credential_detail_fields_layout.addLayout(
            self._build_readonly_detail_row(
                None,
                self.credential_detail_password_input,
                self.toggle_credential_password_button,
                self.copy_credential_password_button,
                centered=True,
            )
        )
        credential_detail_fields_layout.addLayout(
            self._build_readonly_detail_row(
                None,
                self.credential_detail_url_input,
                centered=True,
            )
        )
        credential_detail_fields_page = QWidget()
        credential_detail_fields_page.setObjectName("contentContainer")
        credential_detail_page_layout = QVBoxLayout(credential_detail_fields_page)
        credential_detail_page_layout.setContentsMargins(0, 0, 0, 0)
        credential_detail_page_layout.setSpacing(0)
        credential_detail_page_layout.addStretch(1)
        center_row = QHBoxLayout()
        center_row.setContentsMargins(0, 0, 0, 0)
        center_row.setSpacing(0)
        center_row.addStretch(1)
        center_row.addWidget(credential_detail_outline, 0)
        center_row.addStretch(1)
        credential_detail_page_layout.addLayout(center_row)
        credential_detail_page_layout.addStretch(1)

        self.credential_detail_stack.addWidget(self.credential_detail_message)
        self.credential_detail_stack.addWidget(credential_detail_fields_page)

        self.notes_output = QTextEdit()
        self.notes_output.setReadOnly(True)
        self.notes_output.setPlaceholderText("Note details will appear here.")
        self.note_detail_stack = QStackedWidget()
        self.note_detail_message = self.notes_output

        self.note_detail_title_input = QLineEdit()
        self.note_detail_title_input.setReadOnly(True)
        self.note_detail_title_input.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        self.note_detail_title_input.setMinimumWidth(0)
        self.note_detail_title_input.setMaximumWidth(520)
        self.note_detail_title_input.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        self.note_detail_title_input.setProperty("ghostField", True)
        self.note_detail_title_input.setProperty("autoFilled", True)
        self.note_detail_title_input.setStyleSheet("font-weight: 700; color: #e2e8f0;")

        self.note_detail_type_input = QLineEdit()
        self.note_detail_type_input.setReadOnly(True)
        self.note_detail_type_input.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        self.note_detail_type_input.setMinimumWidth(0)
        self.note_detail_type_input.setMaximumWidth(220)
        self.note_detail_type_input.setSizePolicy(
            QSizePolicy.Policy.Fixed,
            QSizePolicy.Policy.Fixed,
        )
        self.note_detail_type_input.setProperty("ghostField", True)
        self.note_detail_type_input.setProperty("autoFilled", True)

        self.note_detail_tags_input = QLineEdit()
        self.note_detail_tags_input.setReadOnly(True)
        self.note_detail_tags_input.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        self.note_detail_tags_input.setMinimumWidth(0)
        self.note_detail_tags_input.setMaximumWidth(260)
        self.note_detail_tags_input.setSizePolicy(
            QSizePolicy.Policy.Fixed,
            QSizePolicy.Policy.Fixed,
        )
        self.note_detail_tags_input.setProperty("ghostField", True)
        self.note_detail_tags_input.setProperty("autoFilled", True)

        self.note_detail_body_stack = QStackedWidget()
        self.note_detail_body_output = QTextEdit()
        self.note_detail_body_output.setReadOnly(True)
        self.note_detail_body_output.setPlaceholderText("Note content will appear here.")
        self.note_detail_body_output.setMinimumWidth(0)
        self.note_detail_body_output.setMinimumHeight(0)
        self.note_detail_body_output.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        self.note_detail_markdown_output = QTextEdit()
        self.note_detail_markdown_output.setReadOnly(True)
        self.note_detail_markdown_output.setMinimumWidth(0)
        self.note_detail_markdown_output.setMinimumHeight(0)
        self.note_detail_markdown_output.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        self.note_detail_body_stack.addWidget(self.note_detail_body_output)
        self.note_detail_body_stack.addWidget(self.note_detail_markdown_output)
        self._note_detail_plaintext_body = ""
        self._note_detail_ciphertext_body = ""
        self._note_detail_body_is_hidden = False
        self._note_detail_markdown_enabled = False
        self._note_detail_has_markdown = False

        self.toggle_note_body_button = QPushButton("Hide")
        self.toggle_note_body_button.setProperty("tone", "secondary")
        self.toggle_note_body_button.setProperty("hoverGlow", "light")
        self.toggle_note_body_button.clicked.connect(self.run_toggle_note_body_visibility)
        self.toggle_note_markdown_button = QPushButton("Markdown")
        self.toggle_note_markdown_button.setProperty("tone", "secondary")
        self.toggle_note_markdown_button.setProperty("hoverGlow", "light")
        self.toggle_note_markdown_button.setEnabled(False)
        self.toggle_note_markdown_button.clicked.connect(
            self.run_toggle_note_markdown_view
        )

        self.copy_note_body_button = QPushButton("Copy")
        self.copy_note_body_button.setProperty("tone", "secondary")
        self.copy_note_body_button.setProperty("hoverGlow", "light")
        self.copy_note_body_button.clicked.connect(self.run_copy_note_body)
        self.note_copy_feedback_label = QLabel("")
        self.note_copy_feedback_label.setObjectName("sectionHint")
        self.note_copy_feedback_label.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        note_detail_outline = QFrame()
        note_detail_outline.setObjectName("credentialDetailOutline")
        note_detail_outline.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        note_detail_fields_layout = QVBoxLayout(note_detail_outline)
        note_detail_fields_layout.setContentsMargins(16, 16, 16, 16)
        note_detail_fields_layout.setSpacing(12)
        note_header_row = QHBoxLayout()
        note_header_row.setContentsMargins(0, 0, 0, 0)
        note_header_row.setSpacing(12)
        note_header_row.addWidget(self.note_detail_type_input, 0)
        note_header_row.addWidget(self.note_detail_tags_input, 0)
        note_header_row.addWidget(self.note_detail_title_input, 1)
        note_detail_fields_layout.addLayout(note_header_row)
        note_detail_fields_layout.addWidget(self.note_detail_body_stack, 1)
        note_detail_footer_row = QHBoxLayout()
        note_detail_footer_row.setContentsMargins(0, 0, 0, 0)
        note_detail_footer_row.setSpacing(8)
        note_detail_footer_row.addWidget(self.toggle_note_body_button, 0)
        note_detail_footer_row.addWidget(self.toggle_note_markdown_button, 0)
        note_detail_footer_row.addStretch(1)
        note_detail_footer_row.addWidget(self.note_copy_feedback_label, 0)
        note_detail_footer_row.addWidget(self.copy_note_body_button, 0)
        note_detail_fields_layout.addLayout(note_detail_footer_row)

        note_detail_fields_page = QWidget()
        note_detail_fields_page.setObjectName("contentContainer")
        note_detail_page_layout = QVBoxLayout(note_detail_fields_page)
        note_detail_page_layout.setContentsMargins(0, 0, 0, 0)
        note_detail_page_layout.setSpacing(0)
        note_center_row = QHBoxLayout()
        note_center_row.setContentsMargins(0, 0, 0, 0)
        note_center_row.setSpacing(0)
        note_center_row.addWidget(note_detail_outline, 1)
        note_detail_page_layout.addLayout(note_center_row, 1)

        self.note_detail_stack.addWidget(self.note_detail_message)
        self.note_detail_stack.addWidget(note_detail_fields_page)

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
        self.vault_pin_input.setPlaceholderText("••••")
        self.vault_pin_input.setProperty("vaultPinField", True)
        self.vault_pin_input.setProperty("ghostField", True)
        self.vault_pin_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.vault_pin_input.returnPressed.connect(self._handle_vault_pin_return_pressed)

        self.unlock_vault_pin_button = QPushButton("Unlock with PIN")
        self.unlock_vault_pin_button.clicked.connect(self.run_unlock_vault_with_pin)
        self.unlock_vault_pin_button.setProperty("tone", "primary")

        self.enroll_vault_pin_button = QPushButton("Enroll PIN on This Device")
        self.enroll_vault_pin_button.setProperty("tone", "secondary")
        self.enroll_vault_pin_button.setProperty("hoverGlow", "light")
        self.enroll_vault_pin_button.clicked.connect(self.run_enroll_vault_pin)

        self.remove_vault_pin_button = QPushButton("Remove PIN")
        self.remove_vault_pin_button.setProperty("tone", "danger")
        self.remove_vault_pin_button.setProperty("hoverGlow", "danger")
        self.remove_vault_pin_button.clicked.connect(self.run_remove_vault_pin)

        self.lock_now_button = QPushButton("Lock Now")
        self.lock_now_button.setProperty("tone", "danger")
        self.lock_now_button.clicked.connect(self.run_lock_vault_now)

        self.toggle_advanced_recovery_button = QPushButton("PIN Settings")
        self.toggle_advanced_recovery_button.clicked.connect(
            self.toggle_advanced_recovery
        )
        self.toggle_advanced_recovery_button.setProperty("tone", "secondary")

        self.recovery_key_b64_input = QLineEdit()
        self.recovery_key_b64_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.recovery_key_b64_input.setPlaceholderText("Paste Recovery Key here.")
        self.recovery_key_b64_input.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.unlock_with_recovery_key_button = QPushButton("Unlock Vault")
        self.unlock_with_recovery_key_button.clicked.connect(self.run_unlock_with_recovery_key)
        self.unlock_with_recovery_key_button.setProperty("tone", "secondary")

        self.clear_vault_key_button = QPushButton("Lock Vault")
        self.clear_vault_key_button.setProperty("tone", "danger")
        self.clear_vault_key_button.clicked.connect(self.run_clear_vault_key)

        self.file_upload_progress = QProgressBar()
        self.file_upload_progress.setRange(0, 100)
        self.file_upload_progress.setValue(0)
        self.file_upload_progress.setFormat("%p%")

        self.file_download_progress = QProgressBar()
        self.file_download_progress.setRange(0, 100)
        self.file_download_progress.setValue(0)
        self.file_download_progress.setFormat("%p%")

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
        self.generate_password_button.setProperty("tone", "secondary")
        self.generate_password_button.setProperty("hoverGlow", "light")
        self.generate_password_button.clicked.connect(self.run_generate_password)

        self.copy_generated_password_button = QPushButton("Copy Generated Password")
        self.copy_generated_password_button.setProperty("tone", "secondary")
        self.copy_generated_password_button.setProperty("hoverGlow", "light")
        self.copy_generated_password_button.clicked.connect(self.run_copy_generated_password)

        self.quick_crypto_method_select = QComboBox()
        for label, method_key in available_method_labels():
            self.quick_crypto_method_select.addItem(label, method_key)
        self.quick_crypto_method_select.currentIndexChanged.connect(
            self._refresh_quick_crypto_method_state
        )

        self.quick_crypto_help_button = QPushButton("?")
        self.quick_crypto_help_button.setProperty("tone", "secondary")
        self.quick_crypto_help_button.setProperty("hoverGlow", "light")
        self.quick_crypto_help_button.setToolTipDuration(0)

        self.quick_crypto_passphrase_input = QLineEdit()
        self.quick_crypto_passphrase_input.setPlaceholderText("Passphrase")
        self.quick_crypto_passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.quick_crypto_input = QPlainTextEdit()
        self.quick_crypto_input.setPlaceholderText(
            "Type plaintext to encrypt, or decrypt with following format:\n"
            "{\n"
            '  "format": "quick-text-v1",\n'
            '  "method": "base64",\n'
            '  "payload_text": "aGVsbG8="\n'
            "}"
        )
        self.quick_crypto_input.setMinimumHeight(48)
        self.quick_crypto_input.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )

        self.quick_crypto_output = QPlainTextEdit()
        self.quick_crypto_output.setReadOnly(True)
        self.quick_crypto_output.setPlaceholderText(
            "Encrypted output or decrypted plain text will appear here."
        )
        self.quick_crypto_output.setMinimumHeight(48)
        self.quick_crypto_output.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )

        self.quick_encrypt_button = QPushButton("Encrypt")
        self.quick_encrypt_button.setProperty("tone", "secondary")
        self.quick_encrypt_button.setProperty("hoverGlow", "light")
        self.quick_encrypt_button.clicked.connect(self.run_quick_encrypt_text)

        self.quick_decrypt_button = QPushButton("Decrypt")
        self.quick_decrypt_button.setProperty("tone", "secondary")
        self.quick_decrypt_button.setProperty("hoverGlow", "light")
        self.quick_decrypt_button.clicked.connect(self.run_quick_decrypt_text)

        self.quick_copy_output_button = QPushButton("Copy Output")
        self.quick_copy_output_button.setProperty("tone", "secondary")
        self.quick_copy_output_button.setProperty("hoverGlow", "light")
        self.quick_copy_output_button.clicked.connect(self.run_copy_quick_crypto_output)

        self.pin_bootstrap_status_label = QLabel()
        self.pin_bootstrap_status_label.setWordWrap(True)

        self.vault_unlock_source_label = QLabel()
        self.vault_unlock_source_label.setWordWrap(True)

        self.vault_next_step_label = QLabel()
        self.vault_next_step_label.setWordWrap(True)

        self.vault_home_summary_label = QLabel()
        self.vault_home_summary_label.setWordWrap(True)

        self.device_pin_scope_label = QLabel()
        self.device_pin_scope_label.setWordWrap(True)

        self.vault_access_help_button = QPushButton("?")
        self.vault_access_help_button.setProperty("tone", "secondary")
        self.vault_access_help_button.setProperty("hoverGlow", "light")
        self.vault_access_help_button.setToolTipDuration(0)

        self.pin_confirmation_input = QLineEdit()
        self.pin_confirmation_input.setPlaceholderText(
            "Type CONFIRM to change PIN."
        )
        self.pin_confirmation_input.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.new_vault_pin_input = QLineEdit()
        self.new_vault_pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_vault_pin_input.setPlaceholderText(
            f"new device PIN, min {MIN_PIN_LENGTH} chars, local to this device"
        )
        self.new_vault_pin_input.setProperty("newVaultPinField", True)
        self.new_vault_pin_input.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.pin_confirmation_label = QLabel()
        self.pin_confirmation_label.setWordWrap(True)

        advanced_new_pin_row = QHBoxLayout()
        advanced_new_pin_row.setContentsMargins(0, 0, 0, 0)
        advanced_new_pin_row.setSpacing(8)
        advanced_new_pin_row.addWidget(self.new_vault_pin_input, 1)

        advanced_pin_manage_row = QHBoxLayout()
        advanced_pin_manage_row.setContentsMargins(0, 0, 0, 0)
        advanced_pin_manage_row.setSpacing(8)
        advanced_pin_manage_row.addWidget(self.pin_confirmation_input, 1)
        advanced_pin_manage_row.addWidget(self.enroll_vault_pin_button)
        advanced_pin_manage_row.addWidget(self.remove_vault_pin_button)

        advanced_recovery_input_row = QHBoxLayout()
        advanced_recovery_input_row.setContentsMargins(0, 0, 0, 0)
        advanced_recovery_input_row.setSpacing(8)
        advanced_recovery_input_row.addWidget(self.recovery_key_b64_input, 1)
        advanced_recovery_input_row.addWidget(self.unlock_with_recovery_key_button)
        advanced_recovery_input_row.addWidget(self.clear_vault_key_button)

        advanced_recovery_row = QVBoxLayout()
        advanced_recovery_row.setContentsMargins(0, 0, 0, 0)
        advanced_recovery_row.setSpacing(8)
        advanced_recovery_row.addLayout(advanced_new_pin_row)
        advanced_recovery_row.addLayout(advanced_pin_manage_row)
        advanced_recovery_row.addLayout(advanced_recovery_input_row)

        self.advanced_recovery_widget = QWidget()
        self.advanced_recovery_widget.setObjectName("contentContainer")
        self.advanced_recovery_widget.setLayout(advanced_recovery_row)
        self.advanced_recovery_widget.setVisible(False)

        self.reset_credential_create_fields()
        self.reset_note_create_fields()
        self.reset_file_create_fields()

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_credentials_tab(), "Credentials")
        self.tabs.addTab(self._build_notes_tab(), "Notes")
        self.tabs.addTab(self._build_files_tab(), "Files")
        self.tabs.tabBar().hide()
        self.tabs.setCurrentIndex(self.persisted_ui_settings.last_tab_index)
        self.tabs.currentChanged.connect(self._handle_workspace_tab_changed)
        self.workspace_credentials_tab_button = QPushButton("Credentials")
        self.workspace_credentials_tab_button.setProperty("segment", "true")
        self.workspace_credentials_tab_button.setProperty("workspaceCompact", True)
        self.workspace_credentials_tab_button.clicked.connect(
            lambda: self.tabs.setCurrentIndex(0)
        )
        self.workspace_notes_tab_button = QPushButton("Notes")
        self.workspace_notes_tab_button.setProperty("segment", "true")
        self.workspace_notes_tab_button.setProperty("workspaceCompact", True)
        self.workspace_notes_tab_button.clicked.connect(
            lambda: self.tabs.setCurrentIndex(1)
        )
        self.workspace_files_tab_button = QPushButton("Files")
        self.workspace_files_tab_button.setProperty("segment", "true")
        self.workspace_files_tab_button.setProperty("workspaceCompact", True)
        self.workspace_files_tab_button.clicked.connect(
            lambda: self.tabs.setCurrentIndex(2)
        )

        self.header_label = QLabel(
            f"App: {settings.app_name} | Environment: {settings.environment} | API: {self.persisted_ui_settings.api_base_url}"
        )
        self.header_label.setWordWrap(True)

        self.screen_eyebrow_label = QLabel()
        self.screen_eyebrow_label.setObjectName("screenEyebrow")
        self.screen_title_label = QLabel()
        self.screen_title_label.setObjectName("screenTitle")
        self.screen_subtitle_label = QLabel()
        self.screen_subtitle_label.setObjectName("screenSubtitle")
        self.screen_subtitle_label.setWordWrap(True)
        self.theme_toggle_button = QPushButton("Light")
        self.theme_toggle_button.setProperty("nav", "true")
        self.theme_toggle_button.clicked.connect(self.run_toggle_theme)
        self.nav_separator_left_label = QLabel("|")
        self.nav_separator_left_label.setObjectName("navSeparator")
        self.nav_generator_button = QPushButton("Generator")
        self.nav_generator_button.setProperty("nav", "true")
        self.nav_generator_button.clicked.connect(lambda: self._switch_to_screen("generator"))
        self.nav_separator_right_label = QLabel("|")
        self.nav_separator_right_label.setObjectName("navSeparator")
        self.system_service_tab_button = QPushButton("Access")
        self.system_service_tab_button.setProperty("segment", "true")
        self.system_service_tab_button.setProperty("navSegment", "true")
        self.system_service_tab_button.clicked.connect(lambda: self._switch_system_panel("service"))
        self.system_messages_tab_button = QPushButton("System logs")
        self.system_messages_tab_button.setProperty("segment", "true")
        self.system_messages_tab_button.clicked.connect(self._open_system_logs)
        self.vault_access_messages_button = QPushButton("System logs")
        self.vault_access_messages_button.setProperty("segment", "true")
        self.vault_access_messages_button.clicked.connect(self._open_system_logs)
        self.current_system_panel = "service"
        self._system_logs_origin_screen = "system"
        self._system_logs_origin_vault_panel = "access"
        self.vault_access_tab_button = QPushButton("Vault access")
        self.vault_access_tab_button.setProperty("segment", "true")
        self.vault_access_tab_button.clicked.connect(lambda: self._switch_vault_panel("access"))
        self.vault_workspace_tab_button = QPushButton("Vault workspace")
        self.vault_workspace_tab_button.setProperty("segment", "true")
        self.vault_workspace_tab_button.clicked.connect(lambda: self._switch_vault_panel("workspace"))
        self.current_vault_panel = "access"

        self.nav_vault_button = QPushButton("Vault")
        self.nav_vault_button.setProperty("nav", "true")
        self.nav_vault_button.clicked.connect(lambda: self._switch_to_screen("vault"))

        self.screen_stack = QStackedWidget()
        self.current_screen = "system"
        if self.desktop_service.is_authenticated():
            self.current_screen = "vault"
            self.current_vault_panel = "access"

        self.system_workspace_view = SystemWorkspaceView(
            header_label=self.header_label,
            status_label=self.status_label,
            session_label=self.session_label,
            connection_label=self.connection_state_label,
            session_state_label=self.session_state_label,
            vault_state_label=self.vault_state_label,
            api_details_label=self.api_details_label,
            form_widgets={
                "identifier": self.identifier_input,
                "password": self.password_input,
                "device_name": self.device_name_input,
                "platform": self.platform_input,
            },
            auth_buttons={
                "probe": self.probe_button,
                "messages": self.system_messages_tab_button,
                "login": self.login_button,
                "signup": self.sign_up_button,
            },
            preference_widgets={
                "persist_logs": self.remember_session_checkbox,
            },
            utility_buttons={
                "logout": self.logout_button,
                "close": self.close_button,
            },
            log_widgets={
                "copy": self.copy_activity_log_button,
                "clear": self.clear_activity_log_button,
                "back": self.system_messages_back_button,
                "list": self.activity_log_list,
            },
        )
        self.vault_workspace_view = VaultWorkspaceView(
            pin_widgets={
                "input": self.vault_pin_input,
                "unlock": self.unlock_vault_pin_button,
                "enroll": self.enroll_vault_pin_button,
                "remove": self.remove_vault_pin_button,
                "confirm_input": self.pin_confirmation_input,
            },
            recovery_widgets={
                "toggle": self.toggle_advanced_recovery_button,
                "container": self.advanced_recovery_widget,
            },
            help_button=self.vault_access_help_button,
            status_widgets={
                "probe": self.vault_access_probe_button,
                "messages": self.vault_access_messages_button,
                "connection": self.vault_access_connection_state_label,
                "session": self.vault_access_session_state_label,
                "vault": self.vault_access_vault_state_label,
                "status": self.vault_access_status_label,
                "api_details": self.vault_access_api_details_label,
            },
            load_buttons={
                "credentials": self.load_credentials_button,
                "notes": self.load_notes_button,
                "files": self.load_files_button,
                "all": self.load_all_button,
            },
            session_actions={
                "lock": self.lock_now_button,
                "logout": self.vault_logout_button,
            },
            preference_widgets={
                "keep_open": self.keep_vault_open_checkbox,
                "auto_lock_status": self.vault_auto_lock_countdown_label,
            },
            workspace_nav_buttons={
                "credentials": self.workspace_credentials_tab_button,
                "notes": self.workspace_notes_tab_button,
                "files": self.workspace_files_tab_button,
            },
            tabs=self.tabs,
        )
        self.generator_workspace_view = GeneratorWorkspaceView(
            generator_widgets={
                "length": self.password_length_input,
                "upper": self.use_uppercase_checkbox,
                "lower": self.use_lowercase_checkbox,
                "digits": self.use_digits_checkbox,
                "symbols": self.use_symbols_checkbox,
                "output": self.generated_password_output,
                "generate": self.generate_password_button,
                "copy": self.copy_generated_password_button,
                "method": self.quick_crypto_method_select,
                "method_help": self.quick_crypto_help_button,
                "passphrase": self.quick_crypto_passphrase_input,
                "quick_input": self.quick_crypto_input,
                "quick_output": self.quick_crypto_output,
                "encrypt": self.quick_encrypt_button,
                "decrypt": self.quick_decrypt_button,
                "copy_output": self.quick_copy_output_button,
            },
        )

        self.screen_stack.addWidget(self.system_workspace_view)
        self.screen_stack.addWidget(self.vault_workspace_view)
        self.screen_stack.addWidget(self.generator_workspace_view)

        toolbar_frame = QFrame()
        toolbar_frame.setObjectName("toolbarFrame")
        toolbar_layout = QHBoxLayout(toolbar_frame)
        toolbar_layout.setContentsMargins(10, 4, 10, 4)
        toolbar_layout.setSpacing(4)
        toolbar_layout.addStretch(1)
        toolbar_layout.addWidget(self.theme_toggle_button)
        toolbar_layout.addWidget(self.nav_separator_left_label)
        toolbar_layout.addWidget(self.nav_generator_button)
        toolbar_layout.addWidget(self.nav_separator_right_label)
        toolbar_layout.addWidget(self.system_service_tab_button)
        toolbar_layout.addWidget(self.nav_vault_button)
        self.shell_toolbar_frame = toolbar_frame

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.screen_stack, 1)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.credentials_list.currentItemChanged.connect(lambda *_: self._refresh_action_states())
        self.notes_list.currentItemChanged.connect(lambda *_: self._refresh_action_states())
        self.notes_list.currentItemChanged.connect(self._handle_note_selection_changed)
        self.files_list.currentItemChanged.connect(lambda *_: self._refresh_action_states())
        self.files_list.currentItemChanged.connect(self._handle_file_selection_changed)
        self.file_path_input.textChanged.connect(lambda *_: self._refresh_action_states())
        self.file_download_target_input.textChanged.connect(lambda *_: self._refresh_action_states())
        self.vault_pin_input.textChanged.connect(lambda *_: self._refresh_action_states())
        self.vault_pin_input.textChanged.connect(lambda *_: self._refresh_vault_pin_field_style())
        self.vault_pin_input.textChanged.connect(lambda *_: self._maybe_auto_unlock_with_pin())
        self.new_vault_pin_input.textChanged.connect(lambda *_: self._refresh_action_states())
        self.new_vault_pin_input.textChanged.connect(lambda *_: self._refresh_new_vault_pin_field_state())
        self.pin_confirmation_input.textChanged.connect(lambda *_: self._refresh_action_states())
        self.recovery_key_b64_input.textChanged.connect(lambda *_: self._refresh_recovery_key_field_state())

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
        self.vault_auto_lock_countdown_timer = QTimer(self)
        self.vault_auto_lock_countdown_timer.setInterval(1000)
        self.vault_auto_lock_countdown_timer.timeout.connect(
            self._refresh_vault_auto_lock_countdown_label
        )
        self.vault_auto_lock_disabled_blink_timer = QTimer(self)
        self.vault_auto_lock_disabled_blink_timer.setInterval(500)
        self.vault_auto_lock_disabled_blink_timer.timeout.connect(
            self._toggle_vault_auto_lock_disabled_blink
        )

        self.session_auto_logout_timer = QTimer(self)
        self.session_auto_logout_timer.setSingleShot(True)
        self.session_auto_logout_timer.timeout.connect(self._handle_session_auto_logout_timeout)

        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)

        self._apply_theme()
        self._refresh_vault_pin_field_style()
        self._refresh_new_vault_pin_field_state()
        self._refresh_recovery_key_field_state()
        self._refresh_quick_crypto_method_state()
        self._refresh_workspace_nav_buttons()
        self._refresh_credential_filter_buttons()
        self.refresh_session_label()
        self._refresh_system_state_indicators()
        self._refresh_action_states()
        self._refresh_idle_policy()
        self._refresh_navbar_labels()
        self._refresh_note_action_labels()

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
        splitter.setSizes([300, 720])

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(splitter)

        widget = QWidget()
        widget.setObjectName("contentContainer")
        widget.setLayout(layout)
        return widget

    def _build_workspace_card(self, *, title: str | None, hint: str | None, content_layout) -> QFrame:
        card = QFrame()
        card.setObjectName("workspaceCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(10)

        if title:
            title_label = QLabel(title)
            title_label.setObjectName("sectionTitle")
            layout.addWidget(title_label)

        if hint:
            hint_label = QLabel(hint)
            hint_label.setObjectName("sectionHint")
            hint_label.setWordWrap(True)
            layout.addWidget(hint_label)

        if isinstance(content_layout, QWidget):
            layout.addWidget(content_layout, 1)
        else:
            layout.addLayout(content_layout, 1)

        return card

    def _build_readonly_detail_row(
        self,
        label_text: str | None,
        input_widget: QLineEdit,
        *action_buttons: QPushButton,
        centered: bool = False,
    ) -> QVBoxLayout:
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        if label_text:
            label = QLabel(label_text)
            label.setObjectName("sectionHint")
            if centered:
                label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(label)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        if centered:
            row.addStretch(1)
            row.addWidget(input_widget, 0)
        else:
            row.addWidget(input_widget, 1)
        for button in action_buttons:
            row.addWidget(button, 0)
        if centered:
            row.addStretch(1)
        layout.addLayout(row)
        return layout

    def _build_credentials_tab(self) -> QWidget:
        list_actions = QHBoxLayout()
        list_actions.setContentsMargins(0, 0, 0, 0)
        list_actions.setSpacing(8)
        list_actions.addWidget(self.create_credential_button)
        list_actions.addWidget(self.update_credential_button)
        list_actions.addStretch(1)
        list_actions.addWidget(self.delete_credential_button)

        list_content = QVBoxLayout()
        list_content.setContentsMargins(0, 0, 0, 0)
        list_content.setSpacing(14)
        list_content.addLayout(list_actions)
        list_content.addWidget(self.credentials_list, 1)
        filter_row = QHBoxLayout()
        filter_row.setContentsMargins(0, 0, 0, 0)
        filter_row.setSpacing(8)
        filter_row.addStretch(1)
        filter_row.addWidget(self.credentials_active_filter_button)
        filter_row.addWidget(self.credentials_deleted_filter_button)
        filter_row.addStretch(1)
        list_content.addLayout(filter_row)

        left_card = self._build_workspace_card(
            title=None,
            hint=None,
            content_layout=list_content,
        )
        left_card.setObjectName("flatWorkspacePanel")

        detail_content = QVBoxLayout()
        detail_content.setContentsMargins(0, 0, 0, 0)
        detail_content.setSpacing(14)
        detail_content.addWidget(self.credential_detail_stack, 1)

        detail_card = self._build_workspace_card(
            title=None,
            hint=None,
            content_layout=detail_content,
        )
        detail_card.setObjectName("flatWorkspacePanel")

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        content_row = QHBoxLayout()
        content_row.setContentsMargins(0, 0, 0, 0)
        content_row.setSpacing(12)
        content_row.addWidget(left_card, 1)
        content_row.addWidget(detail_card, 3)
        layout.addLayout(content_row)

        widget = QWidget()
        widget.setObjectName("contentContainer")
        widget.setLayout(layout)
        return widget

    def _build_notes_tab(self) -> QWidget:
        list_actions = QHBoxLayout()
        list_actions.setContentsMargins(0, 0, 0, 0)
        list_actions.setSpacing(8)
        list_actions.addWidget(self.create_note_button)
        list_actions.addWidget(self.update_note_button)
        list_actions.addStretch(1)
        list_actions.addWidget(self.delete_note_button)

        list_content = QVBoxLayout()
        list_content.setContentsMargins(0, 0, 0, 0)
        list_content.setSpacing(14)
        list_content.addLayout(list_actions)
        list_content.addWidget(self.notes_list, 1)
        filter_row = QHBoxLayout()
        filter_row.setContentsMargins(0, 0, 0, 0)
        filter_row.setSpacing(8)
        filter_row.addStretch(1)
        filter_row.addWidget(self.notes_active_filter_button)
        filter_row.addWidget(self.notes_deleted_filter_button)
        filter_row.addStretch(1)
        list_content.addLayout(filter_row)

        left_card = self._build_workspace_card(
            title=None,
            hint=None,
            content_layout=list_content,
        )
        left_card.setObjectName("flatWorkspacePanel")
        left_card.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Expanding,
        )

        detail_actions = QHBoxLayout()
        detail_actions.setContentsMargins(0, 0, 0, 0)
        detail_actions.setSpacing(8)
        detail_actions.addStretch(1)

        detail_content = QVBoxLayout()
        detail_content.setContentsMargins(0, 0, 0, 0)
        detail_content.setSpacing(14)
        detail_content.addLayout(detail_actions)
        detail_content.addWidget(self.note_detail_stack, 1)

        detail_card = self._build_workspace_card(
            title=None,
            hint=None,
            content_layout=detail_content,
        )
        detail_card.setObjectName("flatWorkspacePanel")
        detail_card.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        content_row = QHBoxLayout()
        content_row.setContentsMargins(0, 0, 0, 0)
        content_row.setSpacing(12)
        content_row.addWidget(left_card, 1)
        content_row.addWidget(detail_card, 3)
        layout.addLayout(content_row)

        widget = QWidget()
        widget.setObjectName("contentContainer")
        widget.setLayout(layout)
        return widget

    def _build_files_tab(self) -> QWidget:
        upload_actions_layout = QHBoxLayout()
        upload_actions_layout.setContentsMargins(0, 0, 0, 0)
        upload_actions_layout.setSpacing(8)
        upload_actions_layout.addWidget(self.create_file_button)
        upload_actions_layout.addWidget(self.cancel_file_upload_button)
        upload_actions_layout.addWidget(self.reset_file_payload_button)
        upload_actions_layout.addStretch(1)

        upload_path_row = QHBoxLayout()
        upload_path_row.setContentsMargins(0, 0, 0, 0)
        upload_path_row.setSpacing(8)
        upload_path_row.addWidget(self.pick_file_button, 0)
        upload_path_row.addWidget(self.file_path_input, 1)

        upload_runtime_row = QHBoxLayout()
        upload_runtime_row.setContentsMargins(0, 0, 0, 0)
        upload_runtime_row.setSpacing(8)
        upload_runtime_row.addWidget(QLabel("Chunk size"))
        upload_runtime_row.addWidget(self.file_chunk_size_kib_input)
        upload_runtime_row.addStretch(1)

        upload_progress_row = QHBoxLayout()
        upload_progress_row.setContentsMargins(0, 0, 0, 0)
        upload_progress_row.setSpacing(8)
        upload_progress_row.addWidget(QLabel("Upload"))
        upload_progress_row.addWidget(self.file_upload_progress, 1)

        upload_layout = QVBoxLayout()
        upload_layout.setContentsMargins(0, 0, 0, 0)
        upload_layout.setSpacing(10)
        upload_layout.addLayout(upload_actions_layout)
        upload_layout.addLayout(upload_path_row)
        upload_layout.addLayout(upload_runtime_row)
        upload_layout.addLayout(upload_progress_row)
        upload_card = self._build_workspace_card(
            title=None,
            hint=None,
            content_layout=upload_layout,
        )
        upload_card.setObjectName("flatWorkspacePanel")

        top_divider = QFrame()
        top_divider.setObjectName("workspaceDividerLine")
        top_divider.setFrameShape(QFrame.Shape.HLine)
        top_divider.setFixedWidth(280)

        download_actions_layout = QHBoxLayout()
        download_actions_layout.setContentsMargins(0, 0, 0, 0)
        download_actions_layout.setSpacing(8)
        download_actions_layout.addWidget(self.download_file_button)
        download_actions_layout.addWidget(self.cancel_file_download_button)
        download_actions_layout.addStretch(1)

        download_target_row = QHBoxLayout()
        download_target_row.setContentsMargins(0, 0, 0, 0)
        download_target_row.setSpacing(8)
        download_target_row.addWidget(self.pick_download_target_button, 0)
        download_target_row.addWidget(self.file_download_target_input, 1)

        download_progress_row = QHBoxLayout()
        download_progress_row.setContentsMargins(0, 0, 0, 0)
        download_progress_row.setSpacing(8)
        download_progress_row.addWidget(QLabel("Download"))
        download_progress_row.addWidget(self.file_download_progress, 1)

        download_layout = QVBoxLayout()
        download_layout.setContentsMargins(0, 0, 0, 0)
        download_layout.setSpacing(10)
        download_layout.addLayout(download_actions_layout)
        download_layout.addLayout(download_target_row)
        download_layout.addLayout(download_progress_row)
        download_layout.addStretch(1)
        download_card = self._build_workspace_card(
            title=None,
            hint=None,
            content_layout=download_layout,
        )
        download_card.setObjectName("flatWorkspacePanel")

        vertical_divider = QFrame()
        vertical_divider.setObjectName("workspaceDividerLine")
        vertical_divider.setFrameShape(QFrame.Shape.VLine)
        vertical_divider.setFixedWidth(1)

        file_list_layout = QVBoxLayout()
        file_list_layout.setContentsMargins(0, 0, 0, 0)
        file_list_layout.setSpacing(10)
        file_list_layout.addWidget(self.files_list, 1)
        file_list_card = self._build_workspace_card(
            title=None,
            hint=None,
            content_layout=file_list_layout,
        )
        file_list_card.setObjectName("flatWorkspacePanel")

        file_detail_layout = QVBoxLayout()
        file_detail_layout.setContentsMargins(0, 0, 0, 0)
        file_detail_layout.setSpacing(10)
        file_detail_layout.addWidget(self.files_output, 1)
        file_detail_card = self._build_workspace_card(
            title=None,
            hint=None,
            content_layout=file_detail_layout,
        )
        file_detail_card.setObjectName("flatWorkspacePanel")

        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(12)
        top_row.addWidget(upload_card, 3)
        top_row.addWidget(vertical_divider, 0)
        top_row.addWidget(download_card, 2)

        divider_row = QHBoxLayout()
        divider_row.setContentsMargins(0, 0, 0, 0)
        divider_row.addStretch(1)
        divider_row.addWidget(top_divider, 0)
        divider_row.addStretch(1)

        bottom_row = QHBoxLayout()
        bottom_row.setContentsMargins(0, 0, 0, 0)
        bottom_row.setSpacing(12)
        bottom_row.addWidget(file_list_card, 3)
        bottom_row.addWidget(file_detail_card, 2)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.addLayout(top_row, 0)
        layout.addLayout(divider_row, 0)
        layout.addLayout(bottom_row, 1)

        widget = QWidget()
        widget.setObjectName("contentContainer")
        widget.setLayout(layout)
        return widget

    def _resolve_active_screen(self) -> str:
        current = getattr(self, "current_screen", "system")
        if current == "generator":
            return "generator"
        if not self.desktop_service.is_authenticated():
            return "system"
        if current == "vault":
            return "vault"
        return "system"

    def _screen_index(self, screen: str) -> int:
        return {
            "system": 0,
            "vault": 1,
            "generator": 2,
        }.get(screen, 0)

    def _apply_screen_state(self) -> None:
        required_attrs = (
            "screen_stack",
            "screen_eyebrow_label",
            "screen_title_label",
            "screen_subtitle_label",
            "nav_generator_button",
            "nav_vault_button",
        )
        if not all(hasattr(self, attr) for attr in required_attrs):
            return

        screen = self._resolve_active_screen()
        self.current_screen = screen
        self.screen_stack.setCurrentIndex(self._screen_index(screen))

        descriptors = {
            "system": (
                "Screen 1 / System",
                "Probe, connect, and review session state",
                "Use this screen for API reachability, account login, and system messages before moving into vault operations.",
            ),
            "vault": (
                "Screen 2 / Vault",
                "Unlock, manage access, and work in the vault",
                "PIN, recovery, lock, password generation, and the credentials, notes, and files workspace stay together here.",
            ),
            "generator": (
                "Screen 3 / Generator",
                "Generate passwords outside the vault workspace",
                "Use the password generator independently, then copy the result where needed.",
            ),
        }
        eyebrow, title, subtitle = descriptors[screen]
        self.screen_eyebrow_label.setText(eyebrow)
        self.screen_title_label.setText(title)
        self.screen_subtitle_label.setText(subtitle)

        authenticated = self.desktop_service.is_authenticated()
        self.nav_generator_button.setVisible(True)
        self.nav_vault_button.setVisible(True)
        self.nav_generator_button.setEnabled(True)
        self.nav_vault_button.setEnabled(authenticated)
        if hasattr(self, "shell_toolbar_frame"):
            self.shell_toolbar_frame.setVisible(True)
            if (
                screen == "system"
                and hasattr(self, "system_workspace_view")
                and hasattr(self.system_workspace_view, "set_toolbar_widget")
            ):
                self.system_workspace_view.set_toolbar_widget(self.shell_toolbar_frame)
            elif (
                screen == "vault"
                and hasattr(self, "vault_workspace_view")
                and hasattr(self.vault_workspace_view, "set_toolbar_widget")
            ):
                self.vault_workspace_view.set_toolbar_widget(self.shell_toolbar_frame)
            elif (
                screen == "generator"
                and hasattr(self, "generator_workspace_view")
                and hasattr(self.generator_workspace_view, "set_toolbar_widget")
            ):
                self.generator_workspace_view.set_toolbar_widget(self.shell_toolbar_frame)
        if hasattr(self, "system_service_tab_button"):
            show_system_segments = screen == "system"
            self.system_service_tab_button.setVisible(True)
            service_level = "success" if authenticated else "warning"
            if hasattr(self, "status_label"):
                status_level = self.status_label.property("statusLevel")
                if not authenticated and status_level == "error":
                    service_level = "error"
            self.system_service_tab_button.setProperty("segmentLevel", service_level)
            self.system_service_tab_button.setProperty(
                "segmentCurrent",
                show_system_segments and self.current_system_panel == "service",
            )
            self._repolish(self.system_service_tab_button)
        if hasattr(self, "system_messages_tab_button"):
            self.system_messages_tab_button.setProperty(
                "segmentCurrent",
                self.current_screen == "system" and self.current_system_panel == "messages",
            )
            self._repolish(self.system_messages_tab_button)
        if hasattr(self, "vault_access_tab_button"):
            self.vault_access_tab_button.setVisible(False)
            self.vault_workspace_tab_button.setVisible(False)
            vault_segment_level = "success" if authenticated and self._is_vault_unlocked() else "warning"
            self.vault_access_tab_button.setProperty("segmentLevel", vault_segment_level)
            self.vault_access_tab_button.setProperty(
                "segmentCurrent",
                False,
            )
            self.vault_workspace_tab_button.setProperty(
                "segmentCurrent",
                False,
            )
            self._repolish(self.vault_access_tab_button)
            self._repolish(self.vault_workspace_tab_button)
        if screen == "system" and hasattr(self, "system_workspace_view"):
            self.system_workspace_view.set_current_panel(
                getattr(self, "current_system_panel", "service")
            )
        if screen == "vault" and hasattr(self, "vault_workspace_view"):
            self.vault_workspace_view.set_current_panel(
                getattr(self, "current_vault_panel", "access")
            )
        if not authenticated:
            vault_level = "warning"
        elif self._is_vault_unlocked():
            vault_level = "success"
        else:
            vault_level = "warning"
        self.nav_vault_button.setProperty("navLevel", vault_level)
        self.nav_generator_button.setProperty("navCurrent", screen == "generator")
        self.nav_vault_button.setProperty("navCurrent", screen == "vault")
        self._repolish(self.nav_generator_button)
        self._repolish(self.nav_vault_button)

    def _switch_to_screen(self, screen: str) -> None:
        self.current_screen = screen
        self._apply_screen_state()

    def _open_system_logs(self) -> None:
        self._system_logs_origin_screen = self.current_screen
        self._system_logs_origin_vault_panel = getattr(self, "current_vault_panel", "access")
        self._switch_system_panel("messages")

    def _return_from_system_logs(self) -> None:
        origin_screen = getattr(self, "_system_logs_origin_screen", "system")
        if origin_screen == "vault":
            self.current_screen = "vault"
            self.current_vault_panel = getattr(
                self, "_system_logs_origin_vault_panel", "access"
            )
            if hasattr(self, "vault_workspace_view"):
                self.vault_workspace_view.set_current_panel(self.current_vault_panel)
            if self.current_vault_panel == "workspace":
                self._autoload_current_workspace_tab()
            self._apply_screen_state()
            return
        self._switch_system_panel("service")

    def _switch_system_panel(self, panel: str) -> None:
        self.current_screen = "system"
        self.current_system_panel = panel
        if hasattr(self, "system_workspace_view"):
            self.system_workspace_view.set_current_panel(panel)
        self._apply_screen_state()

    def _switch_vault_panel(self, panel: str) -> None:
        self.current_screen = "vault"
        self.current_vault_panel = panel
        if hasattr(self, "vault_workspace_view"):
            self.vault_workspace_view.set_current_panel(panel)
        if panel == "workspace":
            self._autoload_current_workspace_tab()
        self._apply_screen_state()

    def _autoload_current_workspace_tab(self) -> None:
        if not hasattr(self, "tabs"):
            return
        current_index = self.tabs.currentIndex()
        if current_index == 0:
            self.load_credentials()
        elif current_index == 1:
            self.load_notes()
        elif current_index == 2:
            self.load_files()

    def _refresh_workspace_nav_buttons(self) -> None:
        if not hasattr(self, "tabs"):
            return
        current_index = self.tabs.currentIndex()
        button_map = (
            (getattr(self, "workspace_credentials_tab_button", None), 0),
            (getattr(self, "workspace_notes_tab_button", None), 1),
            (getattr(self, "workspace_files_tab_button", None), 2),
        )
        for button, index in button_map:
            if button is None:
                continue
            button.setProperty("segmentCurrent", current_index == index)
            button.setEnabled(self.tabs.isTabEnabled(index))
            self._repolish(button)

    def _refresh_credential_filter_buttons(self) -> None:
        if not hasattr(self, "credentials_active_filter_button"):
            return
        is_active = self.current_credential_filter == "active"
        self.credentials_active_filter_button.setProperty("segmentCurrent", is_active)
        self.credentials_deleted_filter_button.setProperty("segmentCurrent", not is_active)
        self._repolish(self.credentials_active_filter_button)
        self._repolish(self.credentials_deleted_filter_button)

    def _refresh_note_filter_buttons(self) -> None:
        if not hasattr(self, "notes_active_filter_button"):
            return
        is_active = self.current_note_filter == "active"
        self.notes_active_filter_button.setProperty("segmentCurrent", is_active)
        self.notes_deleted_filter_button.setProperty("segmentCurrent", not is_active)
        self._repolish(self.notes_active_filter_button)
        self._repolish(self.notes_deleted_filter_button)

    def _filtered_credential_items(self) -> list[dict]:
        if self.current_credential_filter == "deleted":
            return [
                item for item in self._credential_items_cache
                if str(item.get("state", "")).lower() == "deleted"
            ]
        return [
            item for item in self._credential_items_cache
            if str(item.get("state", "")).lower() != "deleted"
        ]

    def _filtered_note_items(self) -> list[dict]:
        if self.current_note_filter == "deleted":
            return [
                item for item in self._note_items_cache
                if str(item.get("state", "")).lower() == "deleted"
            ]
        return [
            item for item in self._note_items_cache
            if str(item.get("state", "")).lower() != "deleted"
        ]

    def _apply_credential_list_filter(self) -> None:
        filtered_items = self._filtered_credential_items()
        selected_id = self.selected_credential_id
        self.credentials_list.clear()
        for entry in filtered_items:
            widget_item = QListWidgetItem(credential_list_label(entry))
            widget_item.setData(Qt.ItemDataRole.UserRole, entry.get("credential_id"))
            self.credentials_list.addItem(widget_item)

        if filtered_items:
            if selected_id and self._select_credential_item_by_id(selected_id):
                pass
            else:
                self.credentials_list.setCurrentRow(0)
        else:
            self.selected_credential_id = None
            self.selected_credential_current_version = None

        if not filtered_items:
            self._show_credential_detail_message(format_credentials_items(filtered_items))
        self._refresh_credential_filter_buttons()
        self._refresh_action_states()

    def _set_credential_filter(self, filter_name: str) -> None:
        if filter_name not in {"active", "deleted"}:
            return
        self.current_credential_filter = filter_name
        self._apply_credential_list_filter()

    def _apply_note_list_filter(self) -> None:
        filtered_items = self._filtered_note_items()
        selected_id = self.selected_note_id
        self.notes_list.clear()
        for entry in filtered_items:
            widget_item = QListWidgetItem(note_list_label(entry))
            widget_item.setData(Qt.ItemDataRole.UserRole, entry.get("note_id"))
            self.notes_list.addItem(widget_item)

        if filtered_items:
            if selected_id and self._select_note_item_by_id(selected_id):
                pass
            else:
                self.notes_list.setCurrentRow(0)
        else:
            self.selected_note_id = None
            self.selected_note_current_version = None
            self._clear_note_detail_fields()

        if not filtered_items:
            self._show_note_detail_message(format_notes_items(filtered_items))
        self._refresh_note_filter_buttons()
        self._refresh_action_states()

    def _set_note_filter(self, filter_name: str) -> None:
        if filter_name not in {"active", "deleted"}:
            return
        self.current_note_filter = filter_name
        self._apply_note_list_filter()

    def _handle_workspace_tab_changed(self, index: int) -> None:
        if not hasattr(self, "tabs"):
            return
        self._refresh_workspace_nav_buttons()
        if self.current_screen != "vault" or self.current_vault_panel != "workspace":
            return
        if index == 0:
            self.load_credentials()
        elif index == 1:
            self.load_notes()
        elif index == 2:
            self.load_files()

    def _infer_status_severity(self, message: str) -> str:
        lower = message.lower()
        if any(token in lower for token in ("failed", "error", "cannot", "unavailable")):
            return "error"
        if any(token in lower for token in ("warning", "canceled", "cancelled")):
            return "warning"
        if any(token in lower for token in ("succeeded", "success", "completed", "copied", "saved", "selected", "unlocked")):
            return "success"
        return "info"

    def _append_activity_log(self, message: str, *, severity: str | None = None) -> None:
        message = message.strip()
        if not message:
            return
        if message == self._last_activity_message:
            return

        timestamp = datetime.now().strftime("%H:%M:%S")
        level = (severity or self._infer_status_severity(message)).upper()
        item = QListWidgetItem(f"{timestamp}  {level:<7} {message}")
        level = severity or self._infer_status_severity(message)
        palette = _theme_palette(getattr(self, "current_theme", "light"))
        if level == "error":
            item.setForeground(QColor(palette["danger"]))
            item.setBackground(QColor(palette["danger_bg"]))
        elif level == "warning":
            item.setForeground(QColor(palette["warning"]))
        elif level == "success":
            item.setForeground(QColor(palette["success"]))
        else:
            item.setForeground(QColor(palette["text"]))
        self.activity_log_list.insertItem(0, item)
        while self.activity_log_list.count() > 200:
            self.activity_log_list.takeItem(self.activity_log_list.count() - 1)
        self._last_activity_message = message

    def _handle_status_text_change(self, message: str) -> None:
        if not hasattr(self, "activity_log_list"):
            return
        if hasattr(self, "status_label"):
            self.status_label.setProperty(
                "statusLevel", self._infer_status_severity(message)
            )
            self._repolish(self.status_label)
        if hasattr(self, "vault_access_status_label"):
            self.vault_access_status_label.setText(message)
            self.vault_access_status_label.setProperty(
                "statusLevel", self._infer_status_severity(message)
            )
            self.vault_access_status_label.adjustSize()
            self.vault_access_status_label.updateGeometry()
            self._repolish(self.vault_access_status_label)
        self._append_activity_log(message)
        self._refresh_system_state_indicators()

    def _refresh_system_state_indicators(self) -> None:
        if not hasattr(self, "connection_state_label"):
            return

        if self._last_probe_result is None:
            connection_text = "API not tested..."
            connection_level = "warning"
        elif getattr(self._last_probe_result, "error", None):
            connection_text = "API ko."
            connection_level = "error"
        else:
            connection_text = "API ok."
            connection_level = "success"

        if not self.desktop_service.is_authenticated():
            session_text = "Session inactive."
            session_level = "warning"
            vault_text = "Vault locked."
            vault_level = "warning"
        elif self._is_vault_unlocked():
            session_text = "Session active."
            session_level = "success"
            vault_text = "Vault open."
            vault_level = "success"
        else:
            session_text = "Session active."
            session_level = "success"
            vault_text = "Vault locked."
            vault_level = "warning"

        for label in (self.connection_state_label, getattr(self, "vault_access_connection_state_label", None)):
            if label is not None:
                label.setText(connection_text)
                self._set_badge_state(label, connection_level)
        for label in (self.session_state_label, getattr(self, "vault_access_session_state_label", None)):
            if label is not None:
                label.setText(session_text)
                self._set_badge_state(label, session_level)
        for label in (self.vault_state_label, getattr(self, "vault_access_vault_state_label", None)):
            if label is not None:
                label.setText(vault_text)
                self._set_badge_state(label, vault_level)

        probe_meta = []
        probe_succeeded = self._last_probe_result is not None and not getattr(
            self._last_probe_result, "error", None
        )
        if probe_succeeded:
            probe_meta.append(f"Project: {self._last_probe_result.project_name or '-'}")
            probe_meta.append(f"Version: {self._last_probe_result.version or '-'}")
            probe_meta.append(f"Env: {self._last_probe_result.environment or '-'}")
        if probe_succeeded or self.desktop_service.is_authenticated():
            probe_meta.append(f"API: {self.api_client.base_url}")
        probe_meta_text = " | ".join(probe_meta)
        self.api_details_label.setText(probe_meta_text)
        if hasattr(self, "vault_access_api_details_label"):
            self.vault_access_api_details_label.setText(probe_meta_text)

        self._set_button_tone(self.probe_button, "secondary")
        if hasattr(self, "vault_access_probe_button"):
            self._set_button_tone(self.vault_access_probe_button, "secondary")
        self._set_button_tone(self.login_button, "secondary")

    def run_copy_activity_log(self) -> None:
        app = QApplication.instance()
        if app is None:
            self.status_label.setText("Clipboard is unavailable.")
            return
        lines = []
        for index in range(self.activity_log_list.count()):
            item = self.activity_log_list.item(index)
            if item is not None:
                lines.append(item.text())
        app.clipboard().setText("\n".join(lines))
        self.status_label.setText("Diagnostics copied to clipboard.")

    def run_clear_activity_log(self) -> None:
        self.activity_log_list.clear()
        self._last_activity_message = ""
        self.status_label.setText("Activity log cleared.")

    def _handle_remember_session_toggle(self) -> None:
        self._save_ui_preferences()

    def _handle_keep_vault_open_toggle(self) -> None:
        self._refresh_idle_policy()
        self._save_ui_preferences()

    def _repolish(self, widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    def _set_button_tone(self, button: QPushButton, tone: str) -> None:
        button.setProperty("tone", tone)
        self._repolish(button)

    def _set_badge_state(self, label: QLabel, level: str) -> None:
        label.setProperty("statusLevel", level)
        self._repolish(label)

    def _build_stylesheet(self) -> str:
        palette = _theme_palette(self.current_theme)
        ui_assets_dir = (Path(__file__).resolve().parents[1] / "assets" / "ui").as_posix()
        return """
            QWidget {{
                background: {window};
                color: {text};
                font-size: 13px;
                font-family: "{font_family}", "Courier New", "Liberation Mono", "Nimbus Mono PS", monospace;
                font-weight: 500;
            }}
            QLabel {{
                background: transparent;
            }}
            #contentContainer {{
                background: transparent;
                border: 0;
            }}
            #workspaceDividerLine {{
                background: {border};
                border: 0;
            }}
            QPushButton,
            QLineEdit,
            QTextEdit,
            QPlainTextEdit,
            QListWidget,
            QSpinBox,
            QComboBox,
            QLabel,
            QCheckBox,
            QTabBar::tab {{
                font-size: 13px;
            }}
            QLineEdit,
            QTextEdit,
            QPlainTextEdit,
            QListWidget,
            QSpinBox,
            QComboBox {{
                background: {input};
                border: 1px solid {border};
                border-radius: 10px;
                color: {text};
                padding: 6px 8px;
                selection-background-color: {selection};
            }}
            QComboBox {{
                padding-right: 22px;
            }}
            QComboBox::drop-down {{
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 20px;
                border: 0;
                background: {surface};
                border-left: 1px solid {border};
                border-top-right-radius: 10px;
                border-bottom-right-radius: 10px;
            }}
            QComboBox::down-arrow {{
                image: url({spin_down_icon});
                width: 8px;
                height: 6px;
            }}
            QComboBox QAbstractItemView {{
                background: {surface};
                color: {text};
                border: 1px solid {border};
                selection-background-color: {nav_bg};
                selection-color: {text};
            }}
            QSpinBox::up-button,
            QSpinBox::down-button {{
                background: {surface};
                border: 0;
                border-left: 1px solid {border};
                width: 18px;
            }}
            QSpinBox::up-button {{
                border-top-right-radius: 10px;
            }}
            QSpinBox::down-button {{
                border-bottom-right-radius: 10px;
            }}
            QSpinBox::up-button:hover,
            QSpinBox::down-button:hover {{
                background: {surface_alt};
            }}
            QSpinBox::up-arrow {{
                image: url({spin_up_icon});
                width: 8px;
                height: 6px;
            }}
            QSpinBox::down-arrow {{
                image: url({spin_down_icon});
                width: 8px;
                height: 6px;
            }}
            QCheckBox {{
                background: transparent;
                spacing: 4px;
            }}
            #rememberSessionCheckbox:checked {{
                color: {warning};
            }}
            #keepVaultOpenCheckbox:checked {{
                color: {warning};
            }}
            QCheckBox::indicator {{
                background: {surface};
                border: 1px solid {border};
                border-radius: 3px;
                width: 12px;
                height: 12px;
            }}
            QCheckBox::indicator:hover {{
                border-color: #ffffff;
            }}
            QCheckBox::indicator:checked {{
                background: {surface};
                border-color: {text};
                image: url({checkbox_check_icon});
            }}
            QLineEdit:focus,
            QTextEdit:focus,
            QPlainTextEdit:focus,
            QListWidget:focus,
            QSpinBox:focus,
            QComboBox:focus {{
                border: 1px solid {primary};
            }}
            QLineEdit[ghostField="true"] {{
                background: transparent;
                border: 0;
            }}
            QLineEdit[ghostField="true"]:focus {{
                background: transparent;
                border: 0;
            }}
            QLineEdit[ghostField="true"]::placeholder {{
                color: {muted};
            }}
            QLineEdit[vaultPinField="true"]::placeholder {{
                color: {muted};
            }}
            QLineEdit[pinValidity="invalid"] {{
                border-color: #d84b4b;
            }}
            QLineEdit[pinValidity="valid"] {{
                border-color: #1fdc78;
            }}
            QLineEdit[pinValidity="invalid"]:focus {{
                border-color: #d84b4b;
            }}
            QLineEdit[pinValidity="valid"]:focus {{
                border-color: #1fdc78;
            }}
            QLineEdit[recoveryValidity="invalid"],
            QLineEdit[recoveryValidity="invalid"]:focus {{
                border-color: #d84b4b;
            }}
            QLineEdit[recoveryValidity="valid"],
            QLineEdit[recoveryValidity="valid"]:focus {{
                border-color: #1fdc78;
            }}
            QLineEdit[confirmBlink="true"],
            QLineEdit[confirmBlink="true"]:focus {{
                border-color: #d84b4b;
            }}
            QPushButton {{
                background: {surface_alt};
                border: 1px solid {border};
                border-radius: 10px;
                color: {text};
                font-weight: 600;
                min-height: 20px;
                padding: 1px 7px;
            }}
            QPushButton:hover {{
                border-color: {border};
            }}
            QPushButton:pressed {{
                background: {nav_bg};
            }}
            QPushButton:disabled {{
                color: {muted};
                background: {surface_alt};
                border-color: {border};
            }}
            QPushButton[tone="primary"] {{
                background: {primary};
                border-color: {primary};
                color: #ffffff;
            }}
            QPushButton[tone="primary"]:hover {{
                background: {primary_hover};
            }}
            QPushButton[tone="secondary"] {{
                background: {surface_alt};
                border-color: {border};
                color: {text};
            }}
            QPushButton[tone="danger"] {{
                background: {danger_bg};
                border-color: #7f1d1d;
                color: {danger};
            }}
            QPushButton[tone="danger"]:hover {{
                border-color: {danger};
                color: #ff8a8a;
            }}
            QPushButton[hoverGlow="light"]:hover {{
                border-color: #ffffff;
            }}
            QPushButton[hoverGlow="danger"]:hover {{
                border-color: {danger};
                color: #ff8a8a;
            }}
            QPushButton[nav="true"] {{
                background: {nav_bg};
                border: 1px solid {border};
                border-radius: 999px;
                font-size: 10px;
                padding: 1px 6px;
                min-height: 16px;
            }}
            QPushButton[segment="true"][navSegment="true"] {{
                font-size: 10px;
                padding: 1px 6px;
                min-height: 16px;
            }}
            QPushButton[workspaceCompact="true"] {{
                font-size: 8px;
                min-height: 14px;
                padding: 0 8px;
            }}
            QCheckBox[workspaceFooterText="true"],
            QLabel[workspaceFooterText="true"] {{
                font-size: 8px;
            }}
            QPushButton[nav="true"][navLevel="success"] {{
                border-color: {success};
                color: {success};
            }}
            QPushButton[nav="true"][navLevel="warning"] {{
                border-color: {warning};
                color: {warning};
            }}
            QPushButton[nav="true"][navLevel="error"] {{
                border-color: {danger};
                color: {danger};
            }}
            QPushButton[nav="true"]:hover {{
                border-color: #ffffff;
                background: {surface_alt};
            }}
            QPushButton[segment="true"] {{
                background: {surface_alt};
                border: 1px solid {border};
                border-radius: 999px;
                color: {text};
                font-weight: 600;
                padding: 2px 8px;
            }}
            QPushButton[segment="true"]:hover {{
                border-color: #ffffff;
                background: {nav_bg};
            }}
            QPushButton[segment="true"][segmentLevel="success"] {{
                border-color: {success};
                color: {success};
            }}
            QPushButton[segment="true"][segmentLevel="warning"] {{
                border-color: {warning};
                color: {warning};
            }}
            QPushButton[segment="true"][segmentLevel="error"] {{
                border-color: {danger};
                color: {danger};
            }}
            QPushButton[statusRowButton="true"] {{
                font-size: 8px;
                min-height: 16px;
                padding: 1px 6px;
                background: transparent;
                border: 1px solid {border};
                border-radius: 999px;
            }}
            QPushButton[statusRowButton="true"][tone="primary"] {{
                background: transparent;
                border-color: {primary};
                color: {primary};
            }}
            QPushButton[statusRowButton="true"][tone="primary"]:hover {{
                background: {nav_bg};
                border-color: #ffffff;
                color: #ffffff;
            }}
            QPushButton[segment="true"][segmentCurrent="true"] {{
                background: {primary};
                border-color: {primary};
                color: #ffffff;
            }}
            QPushButton[segment="true"][segmentCurrent="true"][segmentLevel="success"] {{
                background: {success};
                border-color: {success};
                color: #ffffff;
            }}
            QPushButton[segment="true"][segmentCurrent="true"][segmentLevel="warning"] {{
                background: {warning};
                border-color: {warning};
                color: #0f172a;
            }}
            QPushButton[segment="true"][segmentCurrent="true"][segmentLevel="error"] {{
                background: {danger};
                border-color: {danger};
                color: #ffffff;
            }}
            QPushButton[nav="true"][navCurrent="true"] {{
                background: {primary};
                border-color: {primary};
                color: #ffffff;
            }}
            QPushButton[nav="true"][navCurrent="true"][navLevel="success"] {{
                background: {success};
                border-color: {success};
                color: #ffffff;
            }}
            QPushButton[nav="true"][navCurrent="true"][navLevel="warning"] {{
                background: {warning};
                border-color: {warning};
                color: #0f172a;
            }}
            QPushButton[nav="true"][navCurrent="true"][navLevel="error"] {{
                background: {danger};
                border-color: {danger};
                color: #ffffff;
            }}
            #surfaceDivider {{
                background: {border};
                border: 0;
            }}
            #subPanel {{
                background: {surface_alt};
                border: 1px solid {border};
                border-radius: 12px;
            }}
            #subPanel[variant="secondary"] {{
                background: {input};
            }}
            QTabWidget::pane {{
                border: 0;
            }}
            QTabBar::tab {{
                background: {surface_alt};
                border: 1px solid {border};
                border-bottom: 0;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                color: {muted};
                padding: 8px 14px;
                margin-right: 4px;
            }}
            QTabBar::tab:selected {{
                background: {surface};
                color: {text};
            }}
            QToolTip {{
                background: {surface_alt};
                border: 1px solid {border};
                border-radius: 8px;
                color: {text};
                font-family: "{font_family}", "Courier New", "Liberation Mono", "Nimbus Mono PS", monospace;
                font-size: 12px;
                font-weight: 400;
                padding: 6px 8px;
            }}
            QLineEdit[autoFilled="true"] {{
                color: #7d8392;
            }}
            QLineEdit[autoFilled="true"]::placeholder {{
                color: #6f7584;
            }}
            #heroFrame,
            #toolbarFrame {{
                background: {surface};
                border: 1px solid {border};
                border-radius: 0;
            }}
            #workspaceCard,
            #detailCard {{
                background: {surface};
                border: 1px solid {border};
                border-radius: 16px;
            }}
            #flatWorkspacePanel {{
                background: transparent;
                border: 0;
                border-radius: 0;
            }}
            #credentialDetailOutline {{
                background: transparent;
                border: 1px solid #213149;
                border-radius: 20px;
            }}
            #workspaceBand {{
                background: transparent;
                border: 0;
            }}
            #workspaceBand[bandRole="header"] {{
                border-bottom: 1px solid #1d2b42;
            }}
            #workspaceBand[bandRole="footer"] {{
                border-top: 1px solid #1d2b42;
            }}
            #surfacePanel {{
                background: {panel};
                border: 1px solid {border};
                border-radius: 0;
            }}
            #surfacePanel[panelVariant="transparent"] {{
                background: transparent;
                border-color: {border};
            }}
            #vaultWorkspace {{
                background: transparent;
                border: 0;
            }}
            #surfacePanel[panelVariant="secondary"],
            #workspaceCard[cardVariant="secondary"],
            #detailCard[cardVariant="secondary"] {{
                background: {surface_alt};
            }}
            #screenEyebrow {{
                color: {muted};
                font-size: 11px;
                font-weight: 700;
                text-transform: uppercase;
            }}
            #navSeparator {{
                background: transparent;
                border: 0;
                color: {muted};
                font-size: 10px;
                padding: 0 1px;
            }}
            #screenTitle {{
                color: {text};
                font-size: 26px;
                font-weight: 700;
            }}
            #screenSubtitle,
            #surfacePanelBody,
            #sectionHint,
            #dialogSummary,
            #sessionBody {{
                color: {muted};
            }}
            #inlineStatusText {{
                background: transparent;
                color: {muted};
                font-size: 11px;
                padding: 0;
            }}
            #inlineStatusText[statusLevel="success"] {{
                color: {success};
            }}
            #inlineStatusText[statusLevel="warning"] {{
                color: {warning};
            }}
            #inlineStatusText[statusLevel="error"] {{
                color: {danger};
            }}
            #inlineStatusText[statusLevel="info"] {{
                color: {muted};
            }}
            #vaultAutoLockCountdown[blinkActive="true"] {{
                color: #ffd36a;
                font-weight: 700;
            }}
            #vaultAutoLockCountdown[blinkActive="false"] {{
                color: {muted};
            }}
            #surfacePanelTitle,
            #sectionTitle {{
                color: {text};
                font-size: 15px;
                font-weight: 700;
            }}
            #fieldLabel {{
                color: {text};
                font-size: 12px;
                font-weight: 700;
            }}
            #statePill {{
                background: {badge_bg};
                border: 1px solid {border};
                border-radius: 999px;
                color: {text};
                font-size: 12px;
                font-weight: 700;
                padding: 7px 12px;
            }}
            #connectionStateText {{
                background: transparent;
                border: 0;
                color: {text};
                font-size: 8px;
                font-family: "{font_family}", "Courier New", "Liberation Mono", "Nimbus Mono PS", monospace;
                font-weight: 400;
                letter-spacing: 0.5px;
                padding: 0;
            }}
            #connectionStateText[statusLevel="success"] {{
                color: #39ff88;
            }}
            #connectionStateText[statusLevel="warning"] {{
                color: #ffd84d;
            }}
            #connectionStateText[statusLevel="error"] {{
                color: #ff5f8a;
            }}
            #statePill[statusLevel="success"] {{
                color: {success};
                border-color: {success};
            }}
            #statePill[statusLevel="warning"] {{
                color: {warning};
                border-color: {warning};
            }}
            #statePill[statusLevel="error"] {{
                color: {danger};
                border-color: {danger};
            }}
            #statePill[statusLevel="info"] {{
                color: {info};
                border-color: {info};
            }}
            #technicalMeta,
            #monoValue {{
                color: {muted};
                background: transparent;
                border: 0;
                border-radius: 0;
                font-family: monospace;
                font-size: 8px;
                padding: 0;
            }}
            #activityLog {{
                background: {input};
                border: 1px solid {border};
                border-radius: 10px;
                padding: 6px;
                font-family: monospace;
            }}
            QPlainTextEdit QScrollBar:vertical,
            #activityLog QScrollBar:vertical {{
                background: {input};
                border: 0;
                border-radius: 999px;
                margin: 0;
                width: 8px;
            }}
            QPlainTextEdit::corner,
            #activityLog::corner {{
                background: {input};
                border: 0;
            }}
            QPlainTextEdit QScrollBar::groove:vertical,
            #activityLog QScrollBar::groove:vertical {{
                background: {input};
                border: 0;
                border-radius: 999px;
            }}
            QPlainTextEdit QScrollBar::handle:vertical,
            #activityLog QScrollBar::handle:vertical {{
                background: {muted};
                border: 0;
                border-radius: 999px;
                min-height: 28px;
            }}
            QPlainTextEdit QScrollBar::handle:vertical:hover,
            #activityLog QScrollBar::handle:vertical:hover {{
                background: {text};
            }}
            QPlainTextEdit QScrollBar::add-line:vertical,
            QPlainTextEdit QScrollBar::sub-line:vertical,
            QPlainTextEdit QScrollBar::add-page:vertical,
            QPlainTextEdit QScrollBar::sub-page:vertical,
            #activityLog QScrollBar::add-line:vertical,
            #activityLog QScrollBar::sub-line:vertical,
            #activityLog QScrollBar::add-page:vertical,
            #activityLog QScrollBar::sub-page:vertical {{
                background: {input};
                border: 0;
                height: 0;
                width: 0;
                margin: 0;
            }}
            QPlainTextEdit QScrollBar::sub-line:vertical,
            #activityLog QScrollBar::sub-line:vertical {{
                subcontrol-origin: margin;
                subcontrol-position: top;
            }}
            QPlainTextEdit QScrollBar::add-line:vertical,
            #activityLog QScrollBar::add-line:vertical {{
                subcontrol-origin: margin;
                subcontrol-position: bottom;
            }}
            QPlainTextEdit QScrollBar::up-arrow:vertical,
            QPlainTextEdit QScrollBar::down-arrow:vertical,
            #activityLog QScrollBar::up-arrow:vertical,
            #activityLog QScrollBar::down-arrow:vertical {{
                background: transparent;
                border: 0;
                width: 0;
                height: 0;
            }}
        """.format(
            font_family=self.ui_font_family,
            spin_up_icon=f"{ui_assets_dir}/spin-up.svg",
            spin_down_icon=f"{ui_assets_dir}/spin-down.svg",
            checkbox_check_icon=f"{ui_assets_dir}/check-white.svg",
            **palette,
        )

    def _apply_theme(self) -> None:
        self.setStyleSheet(self._build_stylesheet())
        if (
            hasattr(self, "note_detail_markdown_output")
            and self._note_detail_markdown_enabled
            and not self._note_detail_body_is_hidden
            and self._note_detail_has_markdown
        ):
            self._render_note_detail_body()
        self._refresh_navbar_labels()

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._refresh_navbar_labels()
        self._refresh_note_action_labels()

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        if self._pending_window_position is not None:
            # Some window managers recenter after the initial show. Re-apply the
            # persisted coordinates once immediately and again after the event
            # loop starts so the saved position wins consistently.
            self._apply_pending_window_position()
            QTimer.singleShot(0, self._apply_pending_window_position)
            QTimer.singleShot(75, self._finalize_pending_window_position)

    def _apply_pending_window_position(self) -> None:
        if self._pending_window_position is None:
            return
        self.move(*self._pending_window_position)

    def _finalize_pending_window_position(self) -> None:
        self._apply_pending_window_position()
        self._pending_window_position = None

    def _refresh_navbar_labels(self) -> None:
        if not hasattr(self, "theme_toggle_button"):
            return
        compact = self.width() < 900
        theme_key = f"theme_{self.current_theme}"
        if compact:
            theme_key = f"{theme_key}_compact"
        self.theme_toggle_button.setText(self._NAVBAR_LABELS[theme_key])
        self.nav_generator_button.setText(
            self._NAVBAR_LABELS["generator_compact" if compact else "generator"]
        )
        self.system_service_tab_button.setText(
            self._NAVBAR_LABELS["access_compact" if compact else "access"]
        )
        self.nav_vault_button.setText(
            self._NAVBAR_LABELS["vault_compact" if compact else "vault"]
        )

    def _refresh_note_action_labels(self) -> None:
        if not hasattr(self, "create_note_button"):
            return
        compact = self.width() < 920
        self.create_note_button.setText(
            self._NOTE_ACTION_LABELS["create"][1 if compact else 0]
        )
        self.update_note_button.setText(
            self._NOTE_ACTION_LABELS["update"][1 if compact else 0]
        )
        self.delete_note_button.setText(
            self._NOTE_ACTION_LABELS["delete"][1 if compact else 0]
        )

    def _refresh_vault_pin_field_style(self) -> None:
        if not hasattr(self, "vault_pin_input"):
            return
        self.vault_pin_input.setStyleSheet("font-size: 64px;")

    def _refresh_new_vault_pin_field_state(self) -> None:
        if not hasattr(self, "new_vault_pin_input"):
            return
        value = self.new_vault_pin_input.text().strip()
        self.new_vault_pin_input.setStyleSheet("")
        if not value:
            state = "idle"
        else:
            try:
                validate_pin(value)
            except ValueError:
                state = "invalid"
            else:
                state = "valid"
        self.new_vault_pin_input.setProperty("pinValidity", state)
        self._repolish(self.new_vault_pin_input)

    def _refresh_recovery_key_field_state(self) -> None:
        if not hasattr(self, "recovery_key_b64_input"):
            return
        if self.recovery_key_b64_input.text().strip():
            self.recovery_key_b64_input.setProperty("recoveryValidity", "idle")
            self.recovery_key_b64_input.setStyleSheet("")
        else:
            self.recovery_key_b64_input.setProperty("recoveryValidity", "idle")
            self.recovery_key_b64_input.setStyleSheet("")
        self._repolish(self.recovery_key_b64_input)

    def _blink_confirm_input(self, remaining_toggles: int = 6, active: bool = True) -> None:
        if not hasattr(self, "pin_confirmation_input"):
            return
        self.pin_confirmation_input.setStyleSheet(
            "border: 1px solid #d84b4b;" if active else ""
        )
        if remaining_toggles <= 1:
            self.pin_confirmation_input.setStyleSheet("")
            return
        QTimer.singleShot(
            120,
            lambda: self._blink_confirm_input(remaining_toggles - 1, not active),
        )

    def _blink_recovery_key_input(self, remaining_toggles: int = 6, active: bool = True) -> None:
        if not hasattr(self, "recovery_key_b64_input"):
            return
        self.recovery_key_b64_input.setStyleSheet(
            "border: 1px solid #d84b4b;" if active else ""
        )
        if remaining_toggles <= 1:
            self.recovery_key_b64_input.setProperty("recoveryValidity", "invalid")
            self.recovery_key_b64_input.setStyleSheet("")
            self._repolish(self.recovery_key_b64_input)
            return
        QTimer.singleShot(
            120,
            lambda: self._blink_recovery_key_input(remaining_toggles - 1, not active),
        )

    def _mark_recovery_key_valid(self) -> None:
        if not hasattr(self, "recovery_key_b64_input"):
            return
        self.recovery_key_b64_input.setProperty("recoveryValidity", "valid")
        self.recovery_key_b64_input.setStyleSheet("")
        self._repolish(self.recovery_key_b64_input)

    def run_toggle_theme(self) -> None:
        self.current_theme = "dark" if self.current_theme == "light" else "light"
        self._apply_theme()
        self._save_ui_preferences()
        self.status_label.setText(
            f"{'Dark' if self.current_theme == 'dark' else 'Light'} theme enabled."
        )

    def _restore_persisted_session(self) -> None:
        remembered = self.persisted_ui_settings.remembered_session
        if not self.persisted_ui_settings.remember_session or not remembered:
            return
        if not all(
            remembered.get(key)
            for key in (
                "identifier",
                "user_id",
                "device_id",
                "session_id",
                "access_token",
                "refresh_token",
                "token_type",
            )
        ):
            return
        self.desktop_service.session_store.set_session(
            DesktopSession(
                identifier=remembered["identifier"],
                user_id=remembered["user_id"],
                device_id=remembered["device_id"],
                session_id=remembered["session_id"],
                access_token=remembered["access_token"],
                refresh_token=remembered["refresh_token"],
                token_type=remembered["token_type"],
            )
        )

    def _remembered_session_payload(self) -> dict[str, str] | None:
        if not hasattr(self, "remember_session_checkbox"):
            return None
        if not self.remember_session_checkbox.isChecked():
            return None
        session = self.desktop_service.current_session()
        if session is None:
            return None
        return {
            "identifier": session.identifier,
            "user_id": session.user_id,
            "device_id": session.device_id,
            "session_id": session.session_id,
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "token_type": session.token_type,
        }

    def _save_ui_preferences(self) -> None:
        default_device_name, default_platform = detect_local_device_defaults()
        normal_geometry = self.normalGeometry()
        window_x = normal_geometry.x() if normal_geometry.isValid() else self.x()
        window_y = normal_geometry.y() if normal_geometry.isValid() else self.y()
        window_width = (
            normal_geometry.width() if normal_geometry.isValid() else self.width()
        )
        window_height = (
            normal_geometry.height() if normal_geometry.isValid() else self.height()
        )
        updated_settings = PersistedUiSettings(
            api_base_url=self.persisted_ui_settings.api_base_url,
            identifier=self.identifier_input.text().strip() or "alice",
            device_name=self.device_name_input.text().strip() or default_device_name,
            platform=self.platform_input.text().strip() or default_platform,
            window_geometry_b64=bytes(self.saveGeometry().toBase64()).decode("ascii"),
            window_x=window_x,
            window_y=window_y,
            window_width=window_width,
            window_height=window_height,
            last_tab_index=self.tabs.currentIndex(),
            theme=self.current_theme,
            remember_session=(
                self.remember_session_checkbox.isChecked()
                if hasattr(self, "remember_session_checkbox")
                else False
            ),
            keep_vault_open=(
                self.keep_vault_open_checkbox.isChecked()
                if hasattr(self, "keep_vault_open_checkbox")
                else False
            ),
            remembered_session=self._remembered_session_payload(),
        )
        self.local_settings_store.save(updated_settings)
        self.persisted_ui_settings = updated_settings

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

    def _set_auth_network_controls_enabled(self, enabled: bool) -> None:
        self.probe_button.setEnabled(enabled)
        self.login_button.setEnabled(enabled)
        if hasattr(self, "sign_up_button"):
            self.sign_up_button.setEnabled(enabled)

    def _cleanup_network_action(self) -> None:
        self._network_action_worker = None
        self._network_action_thread = None
        self._set_auth_network_controls_enabled(True)

    def _on_network_action_failed(self, message: str) -> None:
        self.status_label.setText(message)

    def _start_network_action(self, *, status_text: str, action, on_success) -> None:
        if self._network_action_thread is not None and self._network_action_thread.isRunning():
            self.status_label.setText("Another network action is already running.")
            return

        self.status_label.setText(status_text)
        self._set_auth_network_controls_enabled(False)

        thread = QThread(self)
        worker = NetworkActionWorker(action)
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.succeeded.connect(on_success)
        worker.failed.connect(self._on_network_action_failed)
        worker.succeeded.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.succeeded.connect(lambda _result: self._cleanup_network_action())
        worker.failed.connect(lambda _message: self._cleanup_network_action())
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        self._network_action_thread = thread
        self._network_action_worker = worker
        thread.start()

    def _handle_probe_result(self, result) -> None:
        self._last_probe_result = result
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

    def run_probe(self) -> None:
        self._start_network_action(
            status_text="Probing API...",
            action=self.desktop_service.probe,
            on_success=self._handle_probe_result,
        )

    def _handle_login_result(self, result) -> None:
        if result.error:
            self.status_label.setText(
                "Login failed.\n"
                f"Error: {result.error}"
            )
            return

        session = self.desktop_service.current_session()
        assert session is not None

        self.status_label.setText(
            "Login succeeded.\n"
            f"User ID: {session.user_id}\n"
            f"Device ID: {session.device_id}\n"
            f"Session ID: {session.session_id}\n"
            f"Token type: {session.token_type}"
        )
        self.current_screen = "vault"
        self.current_vault_panel = "access"
        if hasattr(self, "vault_workspace_view"):
            self.vault_workspace_view.set_current_panel("access")
        self.recovery_key_b64_input.clear()
        self.refresh_session_label()
        if not self._is_vault_unlocked():
            self._clear_sensitive_views_for_locked_vault()
        self._refresh_action_states()
        self._refresh_idle_policy()
        self._save_ui_preferences()

    def run_open_signup_dialog(self) -> None:
        default_device_name, default_platform = detect_local_device_defaults()
        dialog = SignupDialog(
            api_base_url=self.api_client.base_url,
            identifier=self.identifier_input.text().strip(),
            device_name=self.device_name_input.text().strip() or default_device_name,
            platform=self.platform_input.text().strip() or default_platform,
            parent=self,
        )
        if dialog.exec():
            self.identifier_input.setText(dialog.registered_identifier)
            self.password_input.clear()
            self.current_screen = "system"
            self.status_label.setText(
                "Registration complete. Recovery key was shown once. "
                "Save it somewhere safe, then log in."
            )
            self.refresh_session_label()
            self._refresh_action_states()

    def run_login(self) -> None:
        identifier = self.identifier_input.text().strip()
        password = self.password_input.text()
        device_name = self.device_name_input.text().strip()
        platform = self.platform_input.text().strip()

        if not identifier:
            self.status_label.setText("Login failed.\nError: Username is required.")
            return
        if not password:
            self.status_label.setText("Login failed.\nError: Password is required.")
            return
        if not device_name:
            self.status_label.setText("Login failed.\nError: Device name is required.")
            return
        if not platform:
            self.status_label.setText("Login failed.\nError: Platform is required.")
            return

        self._start_network_action(
            status_text="Logging in...",
            action=lambda: self.desktop_service.login(
                identifier=identifier,
                password=password,
                device_name=device_name,
                platform=platform,
            ),
            on_success=self._handle_login_result,
        )

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

    def _copy_text_value(self, value: str, success_message: str) -> None:
        if not value or value == "-":
            self.status_label.setText("Nothing to copy.")
            return

        app = QApplication.instance()
        if app is None:
            self.status_label.setText("Clipboard is unavailable.")
            return

        app.clipboard().setText(value)
        self.status_label.setText(success_message)

    def _looks_like_markdown(self, text: str) -> bool:
        return bool(_MARKDOWN_PATTERN.search(text or ""))

    def _refresh_note_markdown_button_state(self) -> None:
        is_enabled = (not self._note_detail_body_is_hidden) and self._note_detail_has_markdown
        self.toggle_note_markdown_button.setEnabled(is_enabled)
        self.toggle_note_markdown_button.setText(
            "Plain" if self._note_detail_markdown_enabled else "Markdown"
        )

    def _render_note_detail_body(self) -> None:
        if self._note_detail_body_is_hidden:
            self.note_detail_body_output.setPlainText(self._note_detail_ciphertext_body)
            self.note_detail_body_stack.setCurrentWidget(self.note_detail_body_output)
            self.note_detail_body_output.moveCursor(
                self.note_detail_body_output.textCursor().MoveOperation.Start
            )
            self._refresh_note_markdown_button_state()
            return

        if self._note_detail_markdown_enabled and self._note_detail_has_markdown:
            self.note_detail_markdown_output.setHtml(
                _render_markdown_preview_html(
                    self._note_detail_plaintext_body,
                    _theme_palette(self.current_theme),
                )
            )
            self.note_detail_body_stack.setCurrentWidget(self.note_detail_markdown_output)
            self.note_detail_markdown_output.moveCursor(
                self.note_detail_markdown_output.textCursor().MoveOperation.Start
            )
        else:
            self.note_detail_body_output.setPlainText(self._note_detail_plaintext_body)
            self.note_detail_body_stack.setCurrentWidget(self.note_detail_body_output)
            self.note_detail_body_output.moveCursor(
                self.note_detail_body_output.textCursor().MoveOperation.Start
            )
        self._refresh_note_markdown_button_state()

    def run_copy_note_body(self) -> None:
        value = (
            self._note_detail_ciphertext_body
            if self._note_detail_body_is_hidden
            else self._note_detail_plaintext_body
        )
        if not value:
            value = self.note_detail_body_output.toPlainText()
        self._copy_text_value(value, "Note content copied to clipboard.")
        if not value or value == "-":
            self.note_copy_feedback_label.setText("")
            return
        self.note_copy_feedback_label.setText("Note copied to clipboard.")
        QTimer.singleShot(1800, self._clear_note_copy_feedback)

    def _clear_note_copy_feedback(self) -> None:
        if hasattr(self, "note_copy_feedback_label"):
            self.note_copy_feedback_label.setText("")

    def run_toggle_note_markdown_view(self) -> None:
        if self._note_detail_body_is_hidden or not self._note_detail_has_markdown:
            return
        self._note_detail_markdown_enabled = not self._note_detail_markdown_enabled
        self._render_note_detail_body()

    def _refresh_quick_crypto_method_state(self) -> None:
        method_key = str(self.quick_crypto_method_select.currentData())
        mode = passphrase_mode_for_method(method_key)
        self.quick_crypto_help_button.setToolTip(method_summary_for_key(method_key))
        if mode == "none":
            self.quick_crypto_passphrase_input.clear()
            self.quick_crypto_passphrase_input.setReadOnly(True)
            self.quick_crypto_passphrase_input.setPlaceholderText("No passphrase needed")
        elif mode == "optional":
            self.quick_crypto_passphrase_input.setReadOnly(False)
            self.quick_crypto_passphrase_input.setPlaceholderText(
                "Optional passphrase / shift seed"
            )
        else:
            self.quick_crypto_passphrase_input.setReadOnly(False)
            self.quick_crypto_passphrase_input.setPlaceholderText("Passphrase required")

    def run_copy_quick_crypto_output(self) -> None:
        output = self.quick_crypto_output.toPlainText().strip()
        if not output:
            self.status_label.setText("Quick crypto output is empty.")
            return

        app = QApplication.instance()
        if app is None:
            self.status_label.setText("Clipboard is unavailable.")
            return

        app.clipboard().setText(output)
        self.status_label.setText("Quick crypto output copied to clipboard.")

    def run_quick_encrypt_text(self) -> None:
        try:
            output = encrypt_text(
                plaintext=self.quick_crypto_input.toPlainText(),
                passphrase=self.quick_crypto_passphrase_input.text(),
                method_key=str(self.quick_crypto_method_select.currentData()),
            )
        except QuickTextCryptoError as exc:
            self.quick_crypto_output.setPlainText(f"Quick encrypt failed.\n{exc}")
            self.status_label.setText(f"Quick encrypt failed.\nError: {exc}")
            return

        self.quick_crypto_output.setPlainText(output)
        self.status_label.setText("Quick text encrypted locally.")

    def run_quick_decrypt_text(self) -> None:
        try:
            plaintext, method_key = decrypt_text(
                envelope_text=self.quick_crypto_input.toPlainText(),
                passphrase=self.quick_crypto_passphrase_input.text(),
            )
        except QuickTextCryptoError as exc:
            self.quick_crypto_output.setPlainText(f"Quick decrypt failed.\n{exc}")
            self.status_label.setText(f"Quick decrypt failed.\nError: {exc}")
            return

        method_index = self.quick_crypto_method_select.findData(method_key)
        if method_index >= 0:
            self.quick_crypto_method_select.setCurrentIndex(method_index)
        self.quick_crypto_output.setPlainText(plaintext)
        self.status_label.setText("Quick text decrypted locally.")

    def _reset_credential_editor_defaults(self) -> tuple[str, str]:
        metadata_text = json.dumps({}, indent=2)
        payload_text = json.dumps({}, indent=2)
        return metadata_text, payload_text

    def _reset_note_editor_defaults(self) -> tuple[str, str, str]:
        metadata_text = json.dumps({}, indent=2)
        payload_text = json.dumps({}, indent=2)
        return "note", metadata_text, payload_text

    def run_open_create_credential_dialog(self) -> None:
        metadata_text, payload_text = self._reset_credential_editor_defaults()
        dialog = CredentialItemEditorDialog(
            title="New Credential",
            summary="Create a new encrypted credential. Labels stay human-readable in the list, while payload content is encrypted before upload.",
            action_text="Create Credential",
            metadata_text=metadata_text,
            payload_text=payload_text,
            reset_callback=self._reset_credential_editor_defaults,
            parent=self,
        )
        if dialog.exec():
            self.credential_metadata_input.setPlainText(dialog.metadata_text())
            self.credential_payload_input.setPlainText(dialog.payload_text())
            self.run_create_credential()

    def run_open_update_credential_dialog(self) -> None:
        if not self.selected_credential_id:
            self.status_label.setText("Load a credential detail first.")
            return
        dialog = CredentialItemEditorDialog(
            title="Edit Credential",
            summary="Review the current decrypted draft, make changes, then save a new encrypted version.",
            action_text="Save Credential",
            metadata_text=self.credential_metadata_input.toPlainText(),
            payload_text=self.credential_payload_input.toPlainText(),
            reset_callback=self._reset_credential_editor_defaults,
            parent=self,
        )
        if dialog.exec():
            self.credential_metadata_input.setPlainText(dialog.metadata_text())
            self.credential_payload_input.setPlainText(dialog.payload_text())
            self.run_update_credential()

    def run_open_create_note_dialog(self) -> None:
        note_type, metadata_text, payload_text = self._reset_note_editor_defaults()
        dialog = NoteItemEditorDialog(
            title="New Note",
            summary="Create a new encrypted note. The note title remains readable in the list while the note body is encrypted.",
            action_text="Create Note",
            metadata_text=metadata_text,
            payload_text=payload_text,
            header_text=self.note_header_input.toPlainText(),
            note_type=note_type,
            reset_callback=self._reset_note_editor_defaults,
            parent=self,
        )
        if dialog.exec():
            self.note_type_input.setText(dialog.note_type_text() or "note")
            self.note_metadata_input.setPlainText(dialog.metadata_text())
            self.note_payload_input.setPlainText(dialog.payload_text())
            self.run_create_note()

    def run_open_update_note_dialog(self) -> None:
        if not self.selected_note_id:
            self.status_label.setText("Load a note detail first.")
            return
        dialog = NoteItemEditorDialog(
            title="Edit Note",
            summary="Review the current decrypted draft, make changes, then save a new encrypted version of the note.",
            action_text="Save Note",
            metadata_text=self.note_metadata_input.toPlainText(),
            payload_text=self.note_payload_input.toPlainText(),
            header_text=self.note_header_input.toPlainText(),
            note_type=self.note_type_input.text().strip() or "note",
            note_type_read_only=True,
            reset_callback=self._reset_note_editor_defaults,
            parent=self,
        )
        if dialog.exec():
            self.note_type_input.setText(dialog.note_type_text() or "note")
            self.note_metadata_input.setPlainText(dialog.metadata_text())
            self.note_payload_input.setPlainText(dialog.payload_text())
            self.run_update_note()

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

        plaintext_app_name, plaintext_username = self._extract_credential_listing_fields(
            plaintext_metadata,
            plaintext_payload,
        )

        prepare_result = self.desktop_service.prepare_credential(device_name=device_name)
        if prepare_result.error:
            self._show_credential_detail_message(
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
            plaintext_app_name=plaintext_app_name,
            plaintext_username=plaintext_username,
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

        plaintext_title = self._extract_note_listing_title(
            plaintext_metadata,
            plaintext_payload,
        )

        prepare_result = self.desktop_service.prepare_note(
            device_name=device_name,
            note_type=note_type,
        )
        if prepare_result.error:
            self._show_note_detail_message(
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
            plaintext_title=plaintext_title,
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

        plaintext_app_name, plaintext_username = self._extract_credential_listing_fields(
            plaintext_metadata,
            plaintext_payload,
        )

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
            plaintext_app_name=plaintext_app_name,
            plaintext_username=plaintext_username,
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

        plaintext_title = self._extract_note_listing_title(
            plaintext_metadata,
            plaintext_payload,
        )

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
            plaintext_title=plaintext_title,
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

    def _handle_successful_vault_pin_unlock(self) -> None:
        self.vault_pin_input.clear()
        self.current_screen = "vault"
        self.current_vault_panel = "workspace"
        if hasattr(self, "vault_workspace_view"):
            self.vault_workspace_view.set_current_panel("workspace")
        self.status_label.setText(
            "Vault unlocked with PIN.\n"
            "Credentials, notes, and files can now use the shared session vault state."
        )
        self.refresh_session_label()
        self._refresh_after_vault_unlock()
        if hasattr(self, "_autoload_current_workspace_tab"):
            self._autoload_current_workspace_tab()
        self._refresh_idle_policy()
        self._refresh_action_states()

    def _handle_vault_pin_return_pressed(self) -> None:
        self.run_unlock_vault_with_pin()
        if not self._is_vault_unlocked():
            self.vault_pin_input.clear()

    def _maybe_auto_unlock_with_pin(self) -> None:
        if not hasattr(self, "desktop_service"):
            return
        if not self.desktop_service.is_authenticated():
            return
        if self._is_vault_unlocked():
            return
        if self.desktop_service.local_pin_bootstrap_status() != "current_account":
            return
        pin_value = self.vault_pin_input.text().strip()
        if len(pin_value) < MIN_PIN_LENGTH:
            return
        try:
            self.desktop_service.unlock_session_vault_with_pin(pin_value)
        except ValueError:
            return
        self._handle_successful_vault_pin_unlock()

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

        self._handle_successful_vault_pin_unlock()

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

        pin_value = self.new_vault_pin_input.text().strip() or self.vault_pin_input.text().strip()
        if not pin_value:
            self.status_label.setText(
                "PIN enrollment failed.\n"
                "Error: Enter a new PIN in Settings or use the main PIN field."
            )
            return

        prior_status = self.desktop_service.local_pin_bootstrap_status()
        if prior_status in {"current_account", "other_account"} and self.pin_confirmation_input.text().strip() != "CONFIRM":
            self.status_label.setText(
                "PIN enrollment failed.\n"
                "Error: Type CONFIRM before changing or replacing the device PIN."
            )
            self._blink_confirm_input()
            self._refresh_action_states()
            return

        try:
            self.desktop_service.enroll_local_pin_bootstrap(pin=pin_value)
        except ValueError as exc:
            self.status_label.setText(
                "PIN enrollment failed.\n"
                f"Error: {exc}"
            )
            return

        self.new_vault_pin_input.clear()
        self.vault_pin_input.clear()
        self.pin_confirmation_input.clear()
        if prior_status == "current_account":
            self.status_label.setText(
                "PIN changed for this device.\n"
                "Future vault unlocks on this desktop will use the updated PIN."
            )
        elif prior_status == "other_account":
            self.status_label.setText(
                "Device PIN replaced for the current account.\n"
                "This changed local desktop trust only; remote vault data was not modified."
            )
        else:
            self.status_label.setText(
                "PIN saved for this device.\n"
                "This PIN is local to this desktop and is not synced elsewhere."
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

        if self.pin_confirmation_input.text().strip() != "CONFIRM":
            self.status_label.setText(
                "Remove PIN failed.\n"
                "Error: Type CONFIRM before removing the device PIN."
            )
            self._blink_confirm_input()
            self._refresh_action_states()
            return

        self.desktop_service.clear_local_pin_bootstrap()
        self.new_vault_pin_input.clear()
        self.pin_confirmation_input.clear()
        if prior_status == "other_account" and identifier_hint:
            self.status_label.setText(
                "Local PIN removed from this device.\n"
                f"The removed enrollment previously belonged to: {identifier_hint}. "
                "Only local desktop trust was changed."
            )
        else:
            self.status_label.setText(
                "Local PIN removed from this device.\n"
                "Only this desktop was affected; Advanced Recovery remains available for fallback unlock."
            )
        self._refresh_action_states()

    def run_lock_vault_now(self) -> None:
        self.run_clear_vault_key()

    def toggle_advanced_recovery(self) -> None:
        visible = not self.advanced_recovery_widget.isVisible()
        self.advanced_recovery_widget.setVisible(visible)
        self.toggle_advanced_recovery_button.setText(
            "Hide PIN Settings" if visible else "PIN Settings"
        )
        self._refresh_action_states()

    def run_unlock_with_recovery_key(self) -> None:
        if not self.desktop_service.is_authenticated():
            self.status_label.setText(
                "Recovery key unlock failed.\n"
                "Error: No active session."
            )
            return

        if self._is_file_job_running():
            self.status_label.setText(
                "A file job is still running.\n"
                "Wait for completion before changing the vault key."
            )
            return

        recovery_key_b64 = self.recovery_key_b64_input.text().strip()
        if not recovery_key_b64:
            self.status_label.setText(
                "Recovery key unlock failed.\n"
                "Error: Recovery key input is empty."
            )
            self._blink_recovery_key_input()
            return

        try:
            self.desktop_service.unlock_session_vault_with_recovery_key(
                recovery_key_b64
            )
        except ValueError as exc:
            self.status_label.setText(
                "Recovery key unlock failed.\n"
                f"Error: {exc}"
            )
            self._blink_recovery_key_input()
            self._refresh_action_states()
            return

        self.recovery_key_b64_input.clear()
        self._mark_recovery_key_valid()
        self.current_screen = "vault"
        self.status_label.setText(
            "Vault unlocked with recovery key.\n"
            "The app fetched wrapped bootstrap material from the API and unwrapped the session vault key locally."
        )
        self.refresh_session_label()
        self._refresh_after_vault_unlock()
        self._refresh_idle_policy()
        self._refresh_action_states()

    def run_clear_vault_key(self) -> None:
        if self._is_file_job_running():
            self.status_label.setText(
                "A file job is still running.\n"
                "Wait for completion before clearing the vault key."
            )
            return

        if not self.desktop_service.is_authenticated():
            self.status_label.setText("No active session.")
            return

        self.desktop_service.clear_session_vault_master_key()
        self.recovery_key_b64_input.clear()
        self.current_screen = "vault"
        self.current_vault_panel = "access"
        if hasattr(self, "vault_workspace_view"):
            self.vault_workspace_view.set_current_panel("access")
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
        metadata_text, payload_text = self._reset_credential_editor_defaults()
        self.credential_metadata_input.setPlainText(metadata_text)
        self.credential_payload_input.setPlainText(payload_text)
        self.credential_header_input.clear()

    def reset_note_create_fields(self) -> None:
        note_type, metadata_text, payload_text = self._reset_note_editor_defaults()
        self.note_type_input.setText(note_type)
        self.note_metadata_input.setPlainText(metadata_text)
        self.note_payload_input.setPlainText(payload_text)
        self.note_header_input.clear()

    def reset_file_create_fields(self) -> None:
        self.file_path_input.clear()
        self.file_download_target_input.clear()
        self.file_chunk_size_kib_input.setValue(8192)
        self.recovery_key_b64_input.clear()
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
        confirmation_ready = self.pin_confirmation_input.text().strip() == "CONFIRM"
        identifier_hint = self.desktop_service.local_pin_bootstrap_identifier_hint()

        if hasattr(self, "login_button"):
            self.login_button.setVisible(not authenticated)
        if hasattr(self, "sign_up_button"):
            self.sign_up_button.setVisible(not authenticated)
        if hasattr(self, "logout_button"):
            self.logout_button.setVisible(authenticated)

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
            self.vault_next_step_label.setText(
                "Next step: log in, then unlock with a local PIN if this device is enrolled or use Advanced Recovery otherwise."
            )
        elif not vault_unlocked and pin_bootstrap_status == "current_account":
            self.vault_unlock_source_label.setText(
                "Vault unlock source: vault is currently locked."
            )
            self.vault_next_step_label.setText(
                "Next step: enter the local PIN for this device. The vault unlocks automatically when the PIN is correct, and Advanced Recovery remains available if needed."
            )
        elif not vault_unlocked and pin_bootstrap_status == "other_account":
            self.vault_unlock_source_label.setText(
                "Vault unlock source: vault is currently locked."
            )
            self.vault_next_step_label.setText(
                "Next step: use Advanced Recovery for this account. The stored local PIN belongs to another account on this device."
            )
        elif not vault_unlocked:
            self.vault_unlock_source_label.setText(
                "Vault unlock source: vault is currently locked."
            )
            self.vault_next_step_label.setText(
                "Next step: use Advanced Recovery to unlock, then enroll a local PIN on this device for everyday use."
            )
        elif unlock_method == "pin":
            self.vault_unlock_source_label.setText(
                "Vault unlock source: PIN on this device."
            )
            self.vault_next_step_label.setText(
                "Vault is unlocked. Sensitive create, update, and decrypt actions are available for this session."
            )
        elif unlock_method == "recovery_key":
            self.vault_unlock_source_label.setText(
                "Vault unlock source: Advanced Recovery key."
            )
            self.vault_next_step_label.setText(
                "Vault is unlocked. Enroll a local PIN on this device if you want a faster everyday unlock path."
            )
        else:
            self.vault_unlock_source_label.setText(
                "Vault unlock source: session vault key is present."
            )
            self.vault_next_step_label.setText(
                "Vault is unlocked. Sensitive create, update, and decrypt actions are available for this session."
            )

        if hasattr(self, "vault_home_summary_label") and not authenticated:
            self.vault_home_summary_label.setText(
                "Log in, then unlock the vault to browse credentials, notes, and files."
            )
        elif hasattr(self, "vault_home_summary_label") and not vault_unlocked:
            self.vault_home_summary_label.setText(
                "Vault access is still visible while locked. Load lists if needed, then unlock to reveal decrypted detail and enable create, update, upload, and download actions."
            )
        elif hasattr(self, "vault_home_summary_label") and unlock_method == "recovery_key":
            self.vault_home_summary_label.setText(
                "Vault is open. You unlocked with recovery, so this is a good time to enroll a local PIN for the next session."
            )
        elif hasattr(self, "vault_home_summary_label"):
            self.vault_home_summary_label.setText(
                "Vault is open. Choose a section, load the latest items, and inspect or edit the selected detail on the right."
            )

        if pin_bootstrap_status == "other_account" and identifier_hint:
            self.device_pin_scope_label.setText(
                "Device PIN scope: local to this desktop only, not synced to other devices, "
                f"and currently associated with another account hint: {identifier_hint}."
            )
        elif pin_bootstrap_status == "current_account":
            self.device_pin_scope_label.setText(
                "Device PIN scope: local to this desktop only, not synced, and currently enrolled for this account. "
                "Advanced Recovery remains available as fallback."
            )
        else:
            self.device_pin_scope_label.setText(
                "Device PIN scope: local to this desktop only and not synced. "
                "Advanced Recovery remains the fallback path if no device PIN is available."
            )

        if not authenticated:
            self.pin_confirmation_label.setText(
                "Confirmation is only required when changing, replacing, or removing a device PIN."
            )
        elif pin_bootstrap_status == "current_account":
            self.pin_confirmation_label.setText(
                "To change or remove the local PIN on this device, type CONFIRM in the confirmation field. "
                "This affects only this desktop."
            )
        elif pin_bootstrap_status == "other_account":
            self.pin_confirmation_label.setText(
                "To replace or remove another account device PIN on this desktop, type CONFIRM in the confirmation field. "
                "This will only change local desktop trust, not remote vault data."
            )
        else:
            self.pin_confirmation_label.setText(
                "No confirmation is required for first-time PIN enrollment on this device."
            )

        if hasattr(self, "vault_access_help_button"):
            if not authenticated:
                help_text = "Log in first. Then unlock with your device PIN or Recovery Key."
            elif pin_bootstrap_status == "current_account":
                help_text = (
                    "Type your PIN to unlock. Open PIN Settings to change it or remove it from this device."
                )
            else:
                help_text = (
                    "No PIN on this device yet. Open PIN Settings, then use your Recovery Key to unlock and enroll one."
                )
            self.vault_access_help_button.setToolTip(help_text)
        
        self.pin_confirmation_input.setToolTip("")
        self.new_vault_pin_input.setToolTip("")
        self.vault_pin_input.setToolTip("")
        self.toggle_advanced_recovery_button.setToolTip("")
        self.enroll_vault_pin_button.setToolTip("")
        self.remove_vault_pin_button.setToolTip("")

        self.vault_pin_input.setEnabled(authenticated)
        self.new_vault_pin_input.setEnabled(authenticated and vault_unlocked)
        self.pin_confirmation_input.setEnabled(
            authenticated and pin_bootstrap_status in {"current_account", "other_account"}
        )
        self.unlock_vault_pin_button.setEnabled(
            authenticated
            and not vault_unlocked
            and pin_bootstrap_status == "current_account"
            and pin_text_present
        )
        new_pin_text_present = bool(
            self.new_vault_pin_input.text().strip() or self.vault_pin_input.text().strip()
        )
        enroll_allowed = authenticated and vault_unlocked and new_pin_text_present
        self.enroll_vault_pin_button.setEnabled(enroll_allowed)
        if pin_bootstrap_status in {"current_account", "other_account"}:
            self.enroll_vault_pin_button.setText("Change PIN")
        else:
            self.enroll_vault_pin_button.setText("Enroll PIN")
        if authenticated and not vault_unlocked and pin_bootstrap_status == "current_account":
            self._set_button_tone(self.unlock_vault_pin_button, "primary")
            self._set_button_tone(self.enroll_vault_pin_button, "secondary")
            self._set_button_tone(self.unlock_with_recovery_key_button, "secondary")
        elif authenticated and not vault_unlocked:
            self._set_button_tone(self.unlock_vault_pin_button, "secondary")
            self._set_button_tone(self.enroll_vault_pin_button, "secondary")
            self._set_button_tone(self.unlock_with_recovery_key_button, "primary")
        else:
            self._set_button_tone(self.unlock_vault_pin_button, "secondary")
            self._set_button_tone(self.enroll_vault_pin_button, "secondary")
            self._set_button_tone(self.unlock_with_recovery_key_button, "secondary")

        self.remove_vault_pin_button.setEnabled(
            authenticated and pin_bootstrap_available and confirmation_ready
        )
        self.lock_now_button.setEnabled(authenticated and vault_unlocked)
        self.vault_logout_button.setEnabled(authenticated and not self._is_file_job_running())
        self.toggle_advanced_recovery_button.setEnabled(authenticated)
        self.recovery_key_b64_input.setEnabled(
            authenticated and not vault_unlocked and recovery_visible
        )
        self.unlock_with_recovery_key_button.setEnabled(
            authenticated and not vault_unlocked and recovery_visible
        )
        self.clear_vault_key_button.setEnabled(vault_unlocked)

        credential_item_selected = self.credentials_list.currentItem() is not None
        credential_detail_loaded = (
            self.selected_credential_id is not None
            and self.selected_credential_current_version is not None
        )
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

        self.create_file_button.setEnabled(file_jobs_idle and vault_unlocked and file_source_ready)
        self.download_file_button.setEnabled(
            file_jobs_idle and vault_unlocked and file_item_selected and file_target_ready
        )
        self._apply_screen_state()

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

    def _locked_placeholder_text(self, kind: str) -> str:
        return "\n".join(
            [
                f"{kind} detail is locked.",
                "Unlock Vault to view decrypted content.",
                "",
                "Sensitive content is hidden while the vault is locked.",
            ]
        )

    def _clear_sensitive_views_for_locked_vault(self) -> None:
        self.reset_credential_create_fields()
        self.reset_note_create_fields()
        self.file_manifest_input.clear()
        self.file_header_input.clear()
        self.file_chunks_input.clear()

        if self.selected_credential_id:
            MainWindow._show_credential_detail_message(
                self,
                self._locked_detail_text(
                    "Credential",
                    {
                        "credential_id": self.selected_credential_id,
                        "current_version": self.selected_credential_current_version or "-",
                    },
                )
            )
        else:
            MainWindow._show_credential_detail_message(
                self,
                self._locked_placeholder_text("Credential")
            )

        if self.selected_note_id:
            MainWindow._show_note_detail_message(
                self,
                self._locked_detail_text(
                    "Note",
                    {
                        "note_id": self.selected_note_id,
                        "current_version": self.selected_note_current_version or "-",
                    },
                )
            )
        else:
            MainWindow._show_note_detail_message(
                self,
                self._locked_placeholder_text("Note")
            )

        self.files_output.setPlainText(
            self._locked_placeholder_text("File")
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
        if hasattr(self, "vault_auto_lock_countdown_timer"):
            self.vault_auto_lock_countdown_timer.stop()
        self.session_auto_logout_timer.stop()

    def _format_duration_label(self, remaining_ms: int) -> str:
        remaining_seconds = max(0, (remaining_ms + 999) // 1000)
        minutes, seconds = divmod(remaining_seconds, 60)
        if minutes:
            return f"{minutes}m {seconds:02d}s"
        return f"{seconds}s"

    def _set_vault_auto_lock_blinking(self, enabled: bool) -> None:
        if not hasattr(self, "vault_auto_lock_countdown_label"):
            return
        if enabled:
            self.vault_auto_lock_countdown_label.setProperty("blinkActive", "true")
            if hasattr(self, "vault_auto_lock_disabled_blink_timer"):
                self.vault_auto_lock_disabled_blink_timer.start()
            self._repolish(self.vault_auto_lock_countdown_label)
            return
        if hasattr(self, "vault_auto_lock_disabled_blink_timer"):
            self.vault_auto_lock_disabled_blink_timer.stop()
        self.vault_auto_lock_countdown_label.setProperty("blinkActive", "false")
        self._repolish(self.vault_auto_lock_countdown_label)

    def _toggle_vault_auto_lock_disabled_blink(self) -> None:
        if not hasattr(self, "vault_auto_lock_countdown_label"):
            return
        current = self.vault_auto_lock_countdown_label.property("blinkActive")
        next_value = "false" if current == "true" else "true"
        self.vault_auto_lock_countdown_label.setProperty("blinkActive", next_value)
        self._repolish(self.vault_auto_lock_countdown_label)

    def _refresh_vault_auto_lock_countdown_label(self) -> None:
        if not hasattr(self, "vault_auto_lock_countdown_label"):
            return
        if not self.desktop_service.is_authenticated():
            MainWindow._set_vault_auto_lock_blinking(self, False)
            self.vault_auto_lock_countdown_label.setText("")
            return
        if not self._is_vault_unlocked():
            MainWindow._set_vault_auto_lock_blinking(self, False)
            self.vault_auto_lock_countdown_label.setText("Vault locked.")
            return
        if (
            hasattr(self, "keep_vault_open_checkbox")
            and self.keep_vault_open_checkbox.isChecked()
        ):
            MainWindow._set_vault_auto_lock_blinking(self, True)
            self.vault_auto_lock_countdown_label.setText("Auto-lock disabled.")
            return
        MainWindow._set_vault_auto_lock_blinking(self, False)
        remaining_ms = self.vault_auto_lock_timer.remainingTime()
        if remaining_ms < 0:
            self.vault_auto_lock_countdown_label.setText(
                f"Auto-lock in {self._format_duration_label(self.vault_auto_lock_timeout_ms)}."
            )
            return
        self.vault_auto_lock_countdown_label.setText(
            f"Auto-lock in {self._format_duration_label(remaining_ms)}."
        )

    def _refresh_idle_policy(self) -> None:
        if not self.desktop_service.is_authenticated():
            self._stop_idle_timers()
            self._refresh_vault_auto_lock_countdown_label()
            return

        self.session_auto_logout_timer.start(self.session_auto_logout_timeout_ms)

        if (
            self._is_vault_unlocked()
            and not (
                hasattr(self, "keep_vault_open_checkbox")
                and self.keep_vault_open_checkbox.isChecked()
            )
        ):
            self.vault_auto_lock_timer.start(self.vault_auto_lock_timeout_ms)
            if hasattr(self, "vault_auto_lock_countdown_timer"):
                self.vault_auto_lock_countdown_timer.start()
        else:
            self.vault_auto_lock_timer.stop()
            if hasattr(self, "vault_auto_lock_countdown_timer"):
                self.vault_auto_lock_countdown_timer.stop()
        self._refresh_vault_auto_lock_countdown_label()

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
            self._refresh_vault_auto_lock_countdown_label()
            self.status_label.setText(
                "Vault auto-lock delayed because a file job is still running."
            )
            return

        self.desktop_service.clear_session_vault_master_key()
        self.recovery_key_b64_input.clear()
        self.current_screen = "vault"
        self._clear_sensitive_views_for_locked_vault()
        self.refresh_session_label()
        self.status_label.setText(
            "Vault auto-locked after inactivity.\n"
            "Sensitive editors were wiped from memory."
        )
        self._refresh_idle_policy()

    def _perform_local_logout(self, status_text: str) -> None:
        self.desktop_service.logout()
        self.password_input.clear()
        self.reset_credential_create_fields()
        self.reset_note_create_fields()
        self.file_manifest_input.clear()
        self.file_header_input.clear()
        self.file_chunks_input.clear()
        self.credentials_list.clear()
        self.notes_list.clear()
        self.files_list.clear()
        MainWindow._show_credential_detail_message(self, "")
        MainWindow._clear_credential_detail_fields(self)
        MainWindow._show_note_detail_message(self, "")
        MainWindow._clear_note_detail_fields(self)
        self.files_output.clear()
        self.recovery_key_b64_input.clear()
        self.selected_credential_id = None
        self.selected_credential_current_version = None
        self.selected_note_id = None
        self.selected_note_current_version = None
        self.current_screen = "system"
        self._stop_idle_timers()
        self.refresh_session_label()
        self._refresh_action_states()
        self.status_label.setText(status_text)
        if hasattr(self, "remember_session_checkbox") and self.remember_session_checkbox.isChecked():
            self.persisted_ui_settings = PersistedUiSettings(
                api_base_url=self.persisted_ui_settings.api_base_url,
                identifier=self.persisted_ui_settings.identifier,
                device_name=self.persisted_ui_settings.device_name,
                platform=self.persisted_ui_settings.platform,
                last_tab_index=self.persisted_ui_settings.last_tab_index,
                theme=self.persisted_ui_settings.theme,
                remember_session=True,
                remembered_session=None,
            )
        self._save_ui_preferences()

    def _show_credential_detail_message(self, text: str) -> None:
        self.credentials_output.setPlainText(text)
        if hasattr(self, "credential_detail_stack"):
            self.credential_detail_stack.setCurrentWidget(self.credential_detail_message)

    def _show_note_detail_message(self, text: str) -> None:
        self.notes_output.setPlainText(text)
        if hasattr(self, "note_detail_stack"):
            self.note_detail_stack.setCurrentWidget(self.note_detail_message)

    def _clear_credential_detail_fields(self) -> None:
        self._credential_detail_password_plaintext = ""
        for attribute_name in (
            "credential_detail_name_input",
            "credential_detail_username_input",
            "credential_detail_password_input",
            "credential_detail_url_input",
            "credential_detail_state_input",
        ):
            widget = getattr(self, attribute_name, None)
            if widget is not None:
                widget.clear()
        if hasattr(self, "credential_detail_password_input"):
            self.credential_detail_password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        if hasattr(self, "toggle_credential_password_button"):
            self.toggle_credential_password_button.setText("Show")
        if hasattr(self, "_refresh_credential_detail_field_widths"):
            self._refresh_credential_detail_field_widths()
        if hasattr(self, "credential_detail_stack"):
            self.credential_detail_stack.setCurrentWidget(self.credential_detail_message)

    def _clear_note_detail_fields(self) -> None:
        self._note_detail_plaintext_body = ""
        self._note_detail_ciphertext_body = ""
        self._note_detail_body_is_hidden = False
        self._note_detail_markdown_enabled = False
        self._note_detail_has_markdown = False
        for attribute_name in (
            "note_detail_title_input",
            "note_detail_type_input",
            "note_detail_tags_input",
        ):
            widget = getattr(self, attribute_name, None)
            if widget is not None:
                widget.clear()
        if hasattr(self, "note_detail_body_output"):
            self.note_detail_body_output.clear()
        if hasattr(self, "note_detail_markdown_output"):
            self.note_detail_markdown_output.clear()
        if hasattr(self, "note_detail_body_stack") and hasattr(self, "note_detail_body_output"):
            self.note_detail_body_stack.setCurrentWidget(self.note_detail_body_output)
        if hasattr(self, "toggle_note_body_button"):
            self.toggle_note_body_button.setText("Hide")
        if hasattr(self, "toggle_note_markdown_button"):
            self.toggle_note_markdown_button.setText("Markdown")
            self.toggle_note_markdown_button.setEnabled(False)
        if hasattr(self, "note_detail_stack"):
            self.note_detail_stack.setCurrentWidget(self.note_detail_message)

    def _random_password_mask(self) -> str:
        return "\u2022" * (8 + secrets.randbelow(7))

    def _set_detail_input_width(
        self,
        input_widget: QLineEdit,
        value: str,
        *,
        masked: bool = False,
        minimum: int = 140,
        maximum: int = 420,
    ) -> None:
        display_text = value or "-"
        if masked:
            display_text = "\u2022" * max(len(value), 8)
        width = input_widget.fontMetrics().horizontalAdvance(display_text) + 34
        input_widget.setFixedWidth(max(minimum, min(maximum, width)))

    def _refresh_credential_detail_field_widths(self) -> None:
        if not hasattr(self, "credential_detail_username_input"):
            return
        self._set_detail_input_width(
            self.credential_detail_username_input,
            self.credential_detail_username_input.text(),
        )
        self._set_detail_input_width(
            self.credential_detail_password_input,
            self.credential_detail_password_input.text(),
        )

    def _refresh_note_detail_field_widths(self) -> None:
        if not hasattr(self, "note_detail_type_input"):
            return
        self._set_detail_input_width(
            self.note_detail_type_input,
            self.note_detail_type_input.text(),
            minimum=48,
            maximum=120,
        )
        self._set_detail_input_width(
            self.note_detail_tags_input,
            self.note_detail_tags_input.text(),
            minimum=60,
            maximum=180,
        )

    def _encrypted_note_body_text(self, item: dict) -> str:
        encrypted_payload = item.get("encrypted_payload")
        if isinstance(encrypted_payload, dict):
            ciphertext = self._first_non_empty_string(
                encrypted_payload.get("ciphertext_b64"),
                encrypted_payload.get("ciphertext"),
            )
            if ciphertext:
                return ciphertext
            return json.dumps(encrypted_payload, indent=2)
        if encrypted_payload not in (None, ""):
            return str(encrypted_payload)
        return "Encrypted note content unavailable."

    def _render_credential_detail_fields(self, item: dict) -> None:
        payload = item.get("plaintext_payload") or {}
        metadata = item.get("plaintext_metadata") or {}
        name_value = self._first_non_empty_string(
            item.get("plaintext_app_name"),
            metadata.get("label"),
            payload.get("app_name"),
            payload.get("service"),
            payload.get("site"),
            payload.get("title"),
        ) or "-"
        username_value = self._first_non_empty_string(
            item.get("plaintext_username"),
            payload.get("username"),
            payload.get("login"),
            payload.get("email"),
            payload.get("account"),
        ) or "-"
        password_value = self._first_non_empty_string(
            payload.get("secret"),
            payload.get("password"),
            payload.get("token"),
            payload.get("api_key"),
        ) or "-"
        url_value = self._first_non_empty_string(
            payload.get("url"),
            payload.get("site"),
            payload.get("uri"),
        ) or "-"
        self.credential_detail_name_input.setText(name_value)
        self.credential_detail_username_input.setText(username_value)
        self._credential_detail_password_plaintext = password_value
        self.credential_detail_password_input.setText(self._random_password_mask())
        self.credential_detail_password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        self.toggle_credential_password_button.setText("Show")
        self.credential_detail_url_input.setText(url_value)
        self._refresh_credential_detail_field_widths()
        if hasattr(self, "credential_detail_stack"):
            self.credential_detail_stack.setCurrentIndex(1)

    def _render_note_detail_fields(self, item: dict) -> None:
        payload = item.get("plaintext_payload") or {}
        metadata = item.get("plaintext_metadata") or {}
        title_value = self._first_non_empty_string(
            item.get("plaintext_title"),
            payload.get("title"),
            metadata.get("label"),
            metadata.get("title"),
        ) or "-"
        note_type_value = self._first_non_empty_string(
            item.get("note_type"),
            payload.get("note_type"),
            metadata.get("note_type"),
        ) or "note"
        raw_tags = metadata.get("tags")
        if isinstance(raw_tags, list):
            tag_values = [str(tag).strip() for tag in raw_tags if str(tag).strip()]
        else:
            tag_values = []
        tags_value = ", ".join(tag_values) if tag_values else "-"
        body_value = self._first_non_empty_string(
            payload.get("content"),
            payload.get("body"),
            payload.get("text"),
            payload.get("summary"),
        )
        if body_value is None:
            body_source = payload if payload else metadata
            body_value = (
                json.dumps(body_source, indent=2)
                if body_source
                else "No decrypted note content available."
            )

        self.note_detail_title_input.setText(title_value)
        self.note_detail_type_input.setText(note_type_value.upper())
        self.note_detail_tags_input.setText(tags_value)
        self._refresh_note_detail_field_widths()
        self.note_detail_title_input.setCursorPosition(0)
        self.note_detail_type_input.setCursorPosition(0)
        self.note_detail_tags_input.setCursorPosition(0)
        self._note_detail_plaintext_body = body_value
        self._note_detail_ciphertext_body = self._encrypted_note_body_text(item)
        self._note_detail_has_markdown = self._looks_like_markdown(body_value)
        self._note_detail_body_is_hidden = True
        self._note_detail_markdown_enabled = False
        self._render_note_detail_body()
        self.toggle_note_body_button.setText("Show")
        if hasattr(self, "note_detail_stack"):
            self.note_detail_stack.setCurrentIndex(1)

    def run_toggle_note_body_visibility(self) -> None:
        if not self._note_detail_plaintext_body and not self._note_detail_ciphertext_body:
            return
        self._note_detail_body_is_hidden = not self._note_detail_body_is_hidden
        if self._note_detail_body_is_hidden:
            self.toggle_note_body_button.setText("Show")
            self._note_detail_markdown_enabled = False
        else:
            self.toggle_note_body_button.setText("Hide")
        self._render_note_detail_body()

    def _toggle_credential_password_visibility(self) -> None:
        if self.toggle_credential_password_button.text() == "Show":
            self.credential_detail_password_input.setText(
                self._credential_detail_password_plaintext or "-"
            )
            self.toggle_credential_password_button.setText("Hide")
            self._refresh_credential_detail_field_widths()
            return

        self.credential_detail_password_input.setText(self._random_password_mask())
        self.toggle_credential_password_button.setText("Show")
        self._refresh_credential_detail_field_widths()

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

    def _handle_note_selection_changed(self, current, previous) -> None:
        if current is None:
            self.selected_note_id = None
            self.selected_note_current_version = None
            self._bind_note_item_to_editors({})
            self._clear_note_detail_fields()
            return
        self.load_note_detail()

    def _handle_file_selection_changed(self, current, previous) -> None:
        if current is None:
            self.files_output.clear()
            return
        self.load_file_detail()

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
            self._show_credential_detail_message(
                f"Credentials fetch failed.\nError: {result.error}"
            )
            self._refresh_action_states()
            return

        self._credential_items_cache = list(result.items)
        self._apply_credential_list_filter()

    def _render_notes(self, result: ObjectListResult) -> None:
        if result.error:
            self._show_note_detail_message(
                f"Notes fetch failed.\nError: {result.error}"
            )
            self._refresh_action_states()
            return

        self._note_items_cache = list(result.items)
        self._apply_note_list_filter()

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
            self._show_credential_detail_message(
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
        self._render_credential_detail_fields(display_item)
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
            self._show_note_detail_message(
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
        self._render_note_detail_fields(display_item)
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
            self._show_credential_detail_message(
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
            self._show_note_detail_message(
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
        self._clear_note_detail_fields()
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
            self._show_credential_detail_message(
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
        self._render_credential_detail_fields(display_item)
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
            self._show_note_detail_message(
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
        self._render_note_detail_fields(display_item)
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
            self.vault_logout_button,
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
            self.file_chunk_size_kib_input,
            self.recovery_key_b64_input,
            self.unlock_with_recovery_key_button,
            self.clear_vault_key_button,
        ]
        for widget in widgets:
            widget.setEnabled(not (upload_busy or download_busy))

        self.cancel_file_upload_button.setEnabled(upload_busy)
        self.cancel_file_download_button.setEnabled(download_busy)

        self.tabs.setTabEnabled(0, not (upload_busy or download_busy))
        self.tabs.setTabEnabled(1, not (upload_busy or download_busy))
        self.tabs.setTabEnabled(2, True)
        self._refresh_workspace_nav_buttons()
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
            self._show_credential_detail_message(
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
            self._show_credential_detail_message(
                self._locked_detail_text("Credential", item)
            )
            self._refresh_action_states()
            return

        display_item = self._decorate_item_detail_for_local_display(item)
        self._bind_credential_item_to_editors(display_item)
        self._render_credential_detail_fields(display_item)
        self._refresh_action_states()

    def _render_note_detail(self, result: ObjectDetailResult) -> None:
        if result.error:
            self.selected_note_id = None
            self.selected_note_current_version = None
            self._show_note_detail_message(
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
            self._show_note_detail_message(self._locked_detail_text("Note", item))
            self._refresh_action_states()
            return

        display_item = self._decorate_item_detail_for_local_display(item)
        self._bind_note_item_to_editors(display_item)
        self._render_note_detail_fields(display_item)
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

    def _first_non_empty_string(self, *values: object) -> str | None:
        for value in values:
            if isinstance(value, str):
                stripped = value.strip()
                if stripped:
                    return stripped
        return None

    def _extract_credential_listing_fields(
        self,
        plaintext_metadata: dict | None,
        plaintext_payload: dict,
    ) -> tuple[str | None, str | None]:
        metadata = plaintext_metadata or {}
        payload = plaintext_payload or {}
        app_name = self._first_non_empty_string(
            metadata.get("label"),
            metadata.get("name"),
            payload.get("app_name"),
            payload.get("service"),
            payload.get("site"),
            payload.get("title"),
        )
        username = self._first_non_empty_string(
            payload.get("username"),
            payload.get("login"),
            payload.get("email"),
            payload.get("account"),
        )
        return app_name, username

    def _extract_note_listing_title(
        self,
        plaintext_metadata: dict | None,
        plaintext_payload: dict,
    ) -> str | None:
        metadata = plaintext_metadata or {}
        payload = plaintext_payload or {}
        return self._first_non_empty_string(
            payload.get("title"),
            metadata.get("title"),
            payload.get("name"),
            metadata.get("label"),
        )

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

    def _select_credential_item_by_id(self, credential_id: str) -> bool:
        for index in range(self.credentials_list.count()):
            item = self.credentials_list.item(index)
            if item.data(Qt.ItemDataRole.UserRole) == credential_id:
                self.credentials_list.setCurrentRow(index)
                return True
        return False

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
            self._refresh_system_state_indicators()
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
        self._refresh_system_state_indicators()
