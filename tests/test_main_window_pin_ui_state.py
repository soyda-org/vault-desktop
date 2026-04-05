import os
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QCheckBox, QLabel, QLineEdit, QListWidget, QPushButton, QTextEdit, QWidget

from app.core.pin_bootstrap import LocalPinBootstrapStore
from app.services.desktop_service import VaultDesktopService
from app.ui.main_window import MainWindow
from vault_crypto.encoding import b64encode_bytes
from vault_crypto.vault_setup import bootstrap_new_vault

VALID_MASTER_KEY_B64 = "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s="


class FakeStack:
    def __init__(self) -> None:
        self.current_index = -1

    def setCurrentIndex(self, index: int) -> None:
        self.current_index = index


class FakeApiClient:
    def __init__(self, *, user_id: str, vault_profile_result=None) -> None:
        self.user_id = user_id
        self.vault_profile_result = vault_profile_result

    def login(self, payload):
        return SimpleNamespace(
            error=None,
            user_id=self.user_id,
            device_id="device_1",
            session_id="session_1",
            access_token="access-token-1",
            refresh_token="refresh-token-1",
            token_type="bearer",
        )

    def refresh(self, payload):
        return SimpleNamespace(
            error=None,
            user_id=self.user_id,
            device_id="device_1",
            session_id="session_1",
            access_token="access-token-2",
            refresh_token="refresh-token-2",
            token_type="bearer",
            status_code=200,
        )

    def probe(self):
        return SimpleNamespace(
            api_base_url="http://127.0.0.1:8000",
            system_ok=True,
            health_ok=True,
            error=None,
        )


    def fetch_vault_profile(self, access_token=None):
        return SimpleNamespace(
            item=self.vault_profile_result,
            error=None,
            status_code=200,
        )


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def make_service(
    tmp_path: Path,
    *,
    user_id: str,
    vault_profile_result=None,
) -> VaultDesktopService:
    return VaultDesktopService(
        api_client=FakeApiClient(
            user_id=user_id,
            vault_profile_result=vault_profile_result,
        ),
        vault_gateway=object(),
        local_pin_bootstrap_store=LocalPinBootstrapStore(
            config_path=tmp_path / "pin_bootstrap.json"
        ),
    )


def login(service: VaultDesktopService, *, identifier: str) -> None:
    result = service.login(
        identifier=identifier,
        password="strong-password",
        device_name="desktop-dev",
        platform="linux",
    )
    assert result.error is None


def make_recovery_fixture(*, user_id: str = "user_1"):
    result = bootstrap_new_vault(
        unlock_passphrase="desktop-recovery-passphrase",
        include_recovery_key=True,
    )
    expected_master_key_b64 = (
        b64encode_bytes(result.vault_root_key)
        if isinstance(result.vault_root_key, bytes)
        else str(result.vault_root_key)
    )
    vault_profile = {
        "user_id": user_id,
        "vault_format_version": 1,
        "active_keyset_version": 1,
        "unlock_salt_b64": result.persisted.unlock_salt_b64,
        "unlock_kdf_params": result.persisted.unlock_kdf_params,
        "wrapped_vault_root_key": result.persisted.wrapped_vault_root_key,
        "recovery_wrapped_vault_root_key": result.persisted.recovery_wrapped_vault_root_key,
    }
    return result.recovery_key_b64, vault_profile, expected_master_key_b64


def make_window_harness(
    tmp_path: Path,
    *,
    user_id: str = "user_1",
    identifier: str = "alice",
    vault_profile_result=None,
):
    window = SimpleNamespace()
    window.desktop_service = make_service(
        tmp_path,
        user_id=user_id,
        vault_profile_result=vault_profile_result,
    )
    login(window.desktop_service, identifier=identifier)

    window.status_label = QLabel()
    window.session_label = QLabel()

    window.credentials_output = QTextEdit()
    window.notes_output = QTextEdit()
    window.files_output = QTextEdit()
    window.file_manifest_input = QTextEdit()
    window.file_header_input = QTextEdit()
    window.file_chunks_input = QTextEdit()

    window.vault_pin_input = QLineEdit()
    window.new_vault_pin_input = QLineEdit()
    window.pin_confirmation_input = QLineEdit()
    window.recovery_key_b64_input = QLineEdit()
    window.file_path_input = QLineEdit()
    window.file_download_target_input = QLineEdit()

    window.pin_bootstrap_status_label = QLabel()
    window.vault_unlock_source_label = QLabel()
    window.vault_next_step_label = QLabel()
    window.vault_home_summary_label = QLabel()
    window.device_pin_scope_label = QLabel()
    window.pin_confirmation_label = QLabel()

    window.unlock_vault_pin_button = QPushButton()
    window.enroll_vault_pin_button = QPushButton()
    window.remove_vault_pin_button = QPushButton()
    window.lock_now_button = QPushButton()
    window.vault_logout_button = QPushButton()
    window.toggle_advanced_recovery_button = QPushButton()
    window.unlock_with_recovery_key_button = QPushButton()
    window.clear_vault_key_button = QPushButton()
    window.keep_vault_open_checkbox = QCheckBox()

    window.load_credential_detail_button = QPushButton()
    window.create_credential_button = QPushButton()
    window.update_credential_button = QPushButton()
    window.delete_credential_button = QPushButton()

    window.load_note_detail_button = QPushButton()
    window.create_note_button = QPushButton()
    window.update_note_button = QPushButton()
    window.delete_note_button = QPushButton()

    window.load_file_detail_button = QPushButton()
    window.create_file_button = QPushButton()
    window.download_file_button = QPushButton()

    window.credentials_list = QListWidget()
    window.notes_list = QListWidget()
    window.files_list = QListWidget()

    window.advanced_recovery_widget = QWidget()
    window.advanced_recovery_widget.setVisible(False)

    window.current_screen = "system"
    window.current_system_panel = "service"
    window.screen_stack = FakeStack()
    window.screen_eyebrow_label = QLabel()
    window.screen_title_label = QLabel()
    window.screen_subtitle_label = QLabel()
    window.shell_toolbar_frame = QWidget()
    window.system_service_tab_button = QPushButton()
    window.system_messages_tab_button = QPushButton()
    window.nav_generator_button = QPushButton()
    window.nav_vault_button = QPushButton()
    window.theme_toggle_button = QPushButton()
    window.system_workspace_view = SimpleNamespace(set_current_panel=lambda panel: None)
    window.tabs = SimpleNamespace(currentIndex=lambda: 0)

    window.selected_credential_id = None
    window.selected_credential_current_version = None
    window.selected_note_id = None
    window.selected_note_current_version = None

    window._is_vault_unlocked = lambda: bool(
        window.desktop_service.current_session_vault_master_key()
    )
    window._is_file_job_running = lambda: False
    window._refresh_action_states = lambda: MainWindow._refresh_action_states(window)
    window._refresh_recovery_key_field_state = lambda: MainWindow._refresh_recovery_key_field_state(window)
    window._blink_recovery_key_input = lambda *args, **kwargs: setattr(window.recovery_key_b64_input, "_blink_called", True)
    window._mark_recovery_key_valid = lambda: window.recovery_key_b64_input.setProperty("recoveryValidity", "valid")
    window.run_unlock_vault_with_pin = lambda: MainWindow.run_unlock_vault_with_pin(window)
    window._handle_successful_vault_pin_unlock = lambda: MainWindow._handle_successful_vault_pin_unlock(window)
    window._handle_vault_pin_return_pressed = lambda: MainWindow._handle_vault_pin_return_pressed(window)
    window._maybe_auto_unlock_with_pin = lambda: MainWindow._maybe_auto_unlock_with_pin(window)
    window._resolve_active_screen = lambda: MainWindow._resolve_active_screen(window)
    window._screen_index = lambda screen: MainWindow._screen_index(window, screen)
    window._apply_screen_state = lambda: MainWindow._apply_screen_state(window)
    window._locked_detail_text = lambda kind, item: MainWindow._locked_detail_text(window, kind, item)
    window._locked_placeholder_text = lambda kind: MainWindow._locked_placeholder_text(window, kind)
    window._clear_sensitive_views_for_locked_vault = lambda: MainWindow._clear_sensitive_views_for_locked_vault(window)
    window.refresh_session_label = lambda: None
    window._refresh_after_vault_unlock = lambda: None
    window._refresh_idle_policy = lambda: None
    window._stop_idle_timers = lambda: None
    window._set_button_tone = lambda button, tone: None
    window._set_badge_state = lambda label, level: None
    window._repolish = lambda widget: None
    window.reset_credential_create_fields = lambda: None
    window.reset_note_create_fields = lambda: None
    window._save_ui_preferences = lambda: None

    return window


def test_first_time_enroll_requires_no_confirmation(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.new_vault_pin_input.setText("1234")

    MainWindow._refresh_action_states(window)

    assert "No local PIN is enrolled" in window.pin_bootstrap_status_label.text()
    assert "Vault is unlocked" in window.vault_next_step_label.text()
    assert "local to this desktop only and not synced" in window.device_pin_scope_label.text()
    assert "No confirmation is required" in window.pin_confirmation_label.text()
    assert window.enroll_vault_pin_button.text() == "Enroll PIN"
    assert window.enroll_vault_pin_button.isEnabled() is True
    assert window.remove_vault_pin_button.isEnabled() is False


def test_current_account_pin_requires_confirm_for_change_and_remove(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.desktop_service.enroll_local_pin_bootstrap(pin="1234")
    window.new_vault_pin_input.setText("5678")

    MainWindow._refresh_action_states(window)

    assert "current account" in window.pin_bootstrap_status_label.text()
    assert "Vault is unlocked" in window.vault_next_step_label.text()
    assert "currently enrolled for this account" in window.device_pin_scope_label.text()
    assert window.enroll_vault_pin_button.text() == "Change PIN"
    assert window.enroll_vault_pin_button.isEnabled() is True
    assert window.remove_vault_pin_button.isEnabled() is False

    window.pin_confirmation_input.setText("CONFIRM")
    MainWindow._refresh_action_states(window)

    assert window.enroll_vault_pin_button.isEnabled() is True
    assert window.remove_vault_pin_button.isEnabled() is True


def test_other_account_pin_disables_unlock_and_requires_confirm(qapp, tmp_path: Path) -> None:
    first = make_service(tmp_path, user_id="user_1")
    login(first, identifier="alice")
    first.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    first.enroll_local_pin_bootstrap(pin="1234")
    first.logout()

    window = make_window_harness(tmp_path, user_id="user_2", identifier="bob")
    window.new_vault_pin_input.setText("1234")

    MainWindow._refresh_action_states(window)

    assert "another account" in window.pin_bootstrap_status_label.text()
    assert "stored local PIN belongs to another account" in window.vault_next_step_label.text()
    assert "another account hint: alice" in window.device_pin_scope_label.text()
    assert "Change PIN" == window.enroll_vault_pin_button.text()
    assert window.unlock_vault_pin_button.isEnabled() is False
    assert window.enroll_vault_pin_button.isEnabled() is False

    window.pin_confirmation_input.setText("CONFIRM")
    window.new_vault_pin_input.setText("5678")
    MainWindow._refresh_action_states(window)

    assert window.enroll_vault_pin_button.isEnabled() is False
    assert window.remove_vault_pin_button.isEnabled() is True


def test_logged_out_routes_to_welcome_screen(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.logout()

    MainWindow._refresh_action_states(window)

    assert window.screen_stack.current_index == 0
    assert window.screen_title_label.text() == "Probe, connect, and review session state"
    assert window.nav_vault_button.isHidden() is False
    assert window.nav_vault_button.isEnabled() is False


def test_generator_screen_remains_available_while_logged_out(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.logout()
    window.current_screen = "generator"

    MainWindow._apply_screen_state(window)

    assert window.screen_stack.current_index == 2
    assert window.screen_title_label.text() == "Generate passwords outside the vault workspace"
    assert window.nav_generator_button.isHidden() is False
    assert window.nav_generator_button.isEnabled() is True


def test_locked_session_routes_to_unlock_screen(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.current_screen = "vault"

    MainWindow._refresh_action_states(window)

    assert window.screen_stack.current_index == 1
    assert window.screen_title_label.text() == "Unlock, manage access, and work in the vault"
    assert window.nav_vault_button.isHidden() is False
    assert window.nav_vault_button.isEnabled() is True


def test_unlocked_session_routes_to_vault_home(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.current_screen = "vault"
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)

    MainWindow._refresh_action_states(window)

    assert window.screen_stack.current_index == 1
    assert window.screen_title_label.text() == "Unlock, manage access, and work in the vault"
    assert "Choose a section" in window.vault_home_summary_label.text()


def test_settings_screen_remains_available_while_authenticated(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.current_screen = "system"

    MainWindow._refresh_action_states(window)

    assert window.screen_stack.current_index == 0
    assert window.screen_title_label.text() == "Probe, connect, and review session state"
    assert window.nav_vault_button.isHidden() is False
    assert window.nav_vault_button.isEnabled() is True


def test_unlock_source_label_tracks_recovery_then_pin(qapp, tmp_path: Path) -> None:
    recovery_key_b64, vault_profile, expected_master_key_b64 = make_recovery_fixture()
    window = make_window_harness(
        tmp_path,
        vault_profile_result=vault_profile,
    )
    MainWindow._refresh_action_states(window)
    assert "vault is currently locked" in window.vault_unlock_source_label.text()

    window.desktop_service.unlock_session_vault_with_recovery_key(recovery_key_b64)
    assert window.desktop_service.current_session_vault_master_key() == expected_master_key_b64
    MainWindow._refresh_action_states(window)
    assert "Advanced Recovery key" in window.vault_unlock_source_label.text()
    assert "Enroll a local PIN on this device" in window.vault_next_step_label.text()

    window.desktop_service.enroll_local_pin_bootstrap(pin="1234")
    window.desktop_service.clear_session_vault_master_key()
    window.desktop_service.unlock_session_vault_with_pin("1234")
    MainWindow._refresh_action_states(window)
    assert "PIN on this device" in window.vault_unlock_source_label.text()
    assert "Vault is unlocked" in window.vault_next_step_label.text()


def test_run_enroll_vault_pin_first_time_sets_local_only_message(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.new_vault_pin_input.setText("1234")

    MainWindow.run_enroll_vault_pin(window)

    assert "PIN saved for this device." in window.status_label.text()
    assert "local to this desktop and is not synced elsewhere" in window.status_label.text()
    assert window.desktop_service.local_pin_bootstrap_status() == "current_account"


def test_run_enroll_vault_pin_accepts_main_pin_field_as_fallback(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.vault_pin_input.setText("1234")

    MainWindow.run_enroll_vault_pin(window)

    assert "PIN saved for this device." in window.status_label.text()
    assert window.desktop_service.local_pin_bootstrap_status() == "current_account"


def test_run_enroll_vault_pin_rejects_change_without_confirm(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.desktop_service.enroll_local_pin_bootstrap(pin="1234")
    window.new_vault_pin_input.setText("5678")
    window._blink_confirm_input = lambda *args, **kwargs: setattr(window.pin_confirmation_input, "_blink_called", True)

    MainWindow.run_enroll_vault_pin(window)

    assert "Type CONFIRM before changing or replacing the device PIN." in window.status_label.text()
    assert getattr(window.pin_confirmation_input, "_blink_called", False) is True


def test_run_remove_vault_pin_with_confirm_clears_local_bootstrap(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.desktop_service.enroll_local_pin_bootstrap(pin="1234")
    window.pin_confirmation_input.setText("CONFIRM")

    MainWindow.run_remove_vault_pin(window)

    assert window.desktop_service.local_pin_bootstrap_status() == "none"
    assert "Only this desktop was affected" in window.status_label.text()


def test_run_unlock_with_recovery_key_uses_recovery_key_material(qapp, tmp_path: Path) -> None:
    recovery_key_b64, vault_profile, expected_master_key_b64 = make_recovery_fixture()
    window = make_window_harness(
        tmp_path,
        vault_profile_result=vault_profile,
    )
    window.recovery_key_b64_input.setText(recovery_key_b64)

    MainWindow.run_unlock_with_recovery_key(window)

    assert window.desktop_service.current_session_vault_master_key() == expected_master_key_b64
    assert "Vault unlocked with recovery key." in window.status_label.text()


def test_run_unlock_with_recovery_key_reports_missing_recovery_material(qapp, tmp_path: Path) -> None:
    window = make_window_harness(
        tmp_path,
        vault_profile_result={
            "user_id": "user_1",
            "vault_format_version": 1,
            "active_keyset_version": 1,
            "unlock_salt_b64": "c2FsdA==",
            "unlock_kdf_params": {"scheme": "argon2id"},
            "wrapped_vault_root_key": {"wrap_scheme": "aes256-kw", "wrapped_key_b64": "YWJj"},
            "recovery_wrapped_vault_root_key": None,
        },
    )
    window.recovery_key_b64_input.setText("abcd")

    MainWindow.run_unlock_with_recovery_key(window)

    assert "Recovery key is not enabled for this vault profile." in window.status_label.text()


def test_run_unlock_with_recovery_key_reports_incorrect_recovery_key(qapp, tmp_path: Path) -> None:
    _, vault_profile, _ = make_recovery_fixture()
    wrong_recovery_key_b64, _, _ = make_recovery_fixture()
    window = make_window_harness(
        tmp_path,
        vault_profile_result=vault_profile,
    )
    window.recovery_key_b64_input.setText(wrong_recovery_key_b64)

    MainWindow.run_unlock_with_recovery_key(window)

    assert "Recovery key unlock failed. Check that the recovery key is correct." in window.status_label.text()


def test_auto_unlock_with_pin_succeeds_when_correct_pin_is_entered(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.desktop_service.enroll_local_pin_bootstrap(pin="1234")
    window.desktop_service.clear_session_vault_master_key()
    window.vault_pin_input.setText("1234")

    MainWindow._maybe_auto_unlock_with_pin(window)

    assert window.desktop_service.current_session_vault_master_key() == VALID_MASTER_KEY_B64
    assert "Vault unlocked with PIN." in window.status_label.text()
    assert window.current_screen == "vault"


def test_enter_on_wrong_pin_clears_field_for_retry(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.desktop_service.enroll_local_pin_bootstrap(pin="1234")
    window.desktop_service.clear_session_vault_master_key()
    window.vault_pin_input.setText("9999")

    MainWindow._handle_vault_pin_return_pressed(window)

    assert window.vault_pin_input.text() == ""
    assert not window._is_vault_unlocked()


def test_logged_out_guidance_prompts_login(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.logout()

    MainWindow._refresh_action_states(window)

    assert "none (logged out)" in window.vault_unlock_source_label.text()
    assert "Next step: log in" in window.vault_next_step_label.text()


def _seed_sensitive_views(window) -> None:
    window.credentials_output.setPlainText("SECRET credential")
    window.notes_output.setPlainText("SECRET note")
    window.files_output.setPlainText("SECRET file")
    window.file_manifest_input.setPlainText("SECRET manifest")
    window.file_header_input.setPlainText("SECRET header")
    window.file_chunks_input.setPlainText("SECRET chunks")


def test_clear_sensitive_views_for_locked_vault_sets_locked_placeholders(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    _seed_sensitive_views(window)

    MainWindow._clear_sensitive_views_for_locked_vault(window)

    assert "Credential detail is locked." in window.credentials_output.toPlainText()
    assert "Note detail is locked." in window.notes_output.toPlainText()
    assert "File detail is locked." in window.files_output.toPlainText()
    assert "SECRET" not in window.credentials_output.toPlainText()
    assert "SECRET" not in window.notes_output.toPlainText()
    assert "SECRET" not in window.files_output.toPlainText()
    assert window.file_manifest_input.toPlainText() == ""
    assert window.file_header_input.toPlainText() == ""
    assert window.file_chunks_input.toPlainText() == ""


def test_run_clear_vault_key_wipes_sensitive_views(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    _seed_sensitive_views(window)

    MainWindow.run_clear_vault_key(window)

    assert window.desktop_service.current_session_vault_master_key() is None
    assert "Vault locked." in window.status_label.text()
    assert "Credential detail is locked." in window.credentials_output.toPlainText()
    assert "Note detail is locked." in window.notes_output.toPlainText()
    assert "File detail is locked." in window.files_output.toPlainText()
    assert window.file_manifest_input.toPlainText() == ""


def test_handle_vault_auto_lock_timeout_wipes_sensitive_views(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    _seed_sensitive_views(window)

    MainWindow._handle_vault_auto_lock_timeout(window)

    assert window.desktop_service.current_session_vault_master_key() is None
    assert "Vault auto-locked after inactivity." in window.status_label.text()
    assert "Credential detail is locked." in window.credentials_output.toPlainText()
    assert "Note detail is locked." in window.notes_output.toPlainText()
    assert "File detail is locked." in window.files_output.toPlainText()


def test_refresh_idle_policy_skips_vault_auto_lock_when_keep_open_enabled(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.keep_vault_open_checkbox.setChecked(True)
    window.session_auto_logout_timer = SimpleNamespace(start=lambda *_: None, stop=lambda: None)
    window.vault_auto_lock_timer = SimpleNamespace(
        start=lambda *_: setattr(window, "_vault_timer_started", True),
        stop=lambda: setattr(window, "_vault_timer_stopped", True),
    )
    window.session_auto_logout_timeout_ms = 1
    window.vault_auto_lock_timeout_ms = 1
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)

    MainWindow._refresh_idle_policy(window)

    assert getattr(window, "_vault_timer_started", False) is False
    assert getattr(window, "_vault_timer_stopped", False) is True


def test_handle_workspace_tab_changed_loads_visible_section(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.current_screen = "vault"
    window.current_vault_panel = "workspace"
    calls: list[str] = []
    window.load_credentials = lambda: calls.append("credentials")
    window.load_notes = lambda: calls.append("notes")
    window.load_files = lambda: calls.append("files")

    MainWindow._handle_workspace_tab_changed(window, 0)
    MainWindow._handle_workspace_tab_changed(window, 1)
    MainWindow._handle_workspace_tab_changed(window, 2)

    assert calls == ["credentials", "notes", "files"]


def test_perform_local_logout_clears_sensitive_outputs(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    _seed_sensitive_views(window)

    MainWindow._perform_local_logout(window, "Logged out.")

    assert window.credentials_output.toPlainText() == ""
    assert window.notes_output.toPlainText() == ""
    assert window.files_output.toPlainText() == ""
    assert window.file_manifest_input.toPlainText() == ""
    assert window.file_header_input.toPlainText() == ""
    assert window.file_chunks_input.toPlainText() == ""
    assert window.status_label.text() == "Logged out."
