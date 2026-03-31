import os
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QListWidget, QPushButton, QWidget

from app.core.pin_bootstrap import LocalPinBootstrapStore
from app.services.desktop_service import VaultDesktopService
from app.ui.main_window import MainWindow

VALID_MASTER_KEY_B64 = "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s="


class FakeApiClient:
    def __init__(self, *, user_id: str) -> None:
        self.user_id = user_id

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


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def make_service(tmp_path: Path, *, user_id: str) -> VaultDesktopService:
    return VaultDesktopService(
        api_client=FakeApiClient(user_id=user_id),
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


def make_window_harness(tmp_path: Path, *, user_id: str = "user_1", identifier: str = "alice"):
    window = SimpleNamespace()
    window.desktop_service = make_service(tmp_path, user_id=user_id)
    login(window.desktop_service, identifier=identifier)

    window.status_label = QLabel()
    window.session_label = QLabel()

    window.vault_pin_input = QLineEdit()
    window.pin_confirmation_input = QLineEdit()
    window.file_master_key_b64_input = QLineEdit()
    window.file_path_input = QLineEdit()
    window.file_download_target_input = QLineEdit()

    window.pin_bootstrap_status_label = QLabel()
    window.vault_unlock_source_label = QLabel()
    window.device_pin_scope_label = QLabel()
    window.pin_confirmation_label = QLabel()

    window.unlock_vault_pin_button = QPushButton()
    window.enroll_vault_pin_button = QPushButton()
    window.remove_vault_pin_button = QPushButton()
    window.lock_now_button = QPushButton()
    window.toggle_advanced_recovery_button = QPushButton()
    window.unlock_session_key_button = QPushButton()
    window.clear_session_key_button = QPushButton()

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

    window.selected_credential_id = None
    window.selected_credential_current_version = None
    window.selected_note_id = None
    window.selected_note_current_version = None

    window._is_vault_unlocked = lambda: bool(
        window.desktop_service.current_session_vault_master_key()
    )
    window._is_file_job_running = lambda: False
    window._refresh_action_states = lambda: MainWindow._refresh_action_states(window)

    return window


def test_first_time_enroll_requires_no_confirmation(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.vault_pin_input.setText("1234")

    MainWindow._refresh_action_states(window)

    assert "No local PIN is enrolled" in window.pin_bootstrap_status_label.text()
    assert "local to this desktop only and not synced" in window.device_pin_scope_label.text()
    assert "No confirmation is required" in window.pin_confirmation_label.text()
    assert window.enroll_vault_pin_button.text() == "Enroll PIN on This Device"
    assert window.enroll_vault_pin_button.isEnabled() is True
    assert window.remove_vault_pin_button.isEnabled() is False


def test_current_account_pin_requires_confirm_for_change_and_remove(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.desktop_service.enroll_local_pin_bootstrap(pin="1234")
    window.vault_pin_input.setText("5678")

    MainWindow._refresh_action_states(window)

    assert "current account" in window.pin_bootstrap_status_label.text()
    assert "currently enrolled for this account" in window.device_pin_scope_label.text()
    assert window.enroll_vault_pin_button.text() == "Change PIN on This Device"
    assert window.enroll_vault_pin_button.isEnabled() is False
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
    window.vault_pin_input.setText("1234")

    MainWindow._refresh_action_states(window)

    assert "another account" in window.pin_bootstrap_status_label.text()
    assert "another account hint: alice" in window.device_pin_scope_label.text()
    assert "Replace PIN for Current Account" == window.enroll_vault_pin_button.text()
    assert window.unlock_vault_pin_button.isEnabled() is False
    assert window.enroll_vault_pin_button.isEnabled() is False

    window.pin_confirmation_input.setText("CONFIRM")
    MainWindow._refresh_action_states(window)

    assert window.enroll_vault_pin_button.isEnabled() is False
    assert window.remove_vault_pin_button.isEnabled() is True


def test_unlock_source_label_tracks_recovery_then_pin(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    MainWindow._refresh_action_states(window)
    assert "vault is currently locked" in window.vault_unlock_source_label.text()

    window.desktop_service.unlock_session_vault_with_recovery_key(VALID_MASTER_KEY_B64)
    MainWindow._refresh_action_states(window)
    assert "Advanced Recovery key" in window.vault_unlock_source_label.text()

    window.desktop_service.enroll_local_pin_bootstrap(pin="1234")
    window.desktop_service.clear_session_vault_master_key()
    window.desktop_service.unlock_session_vault_with_pin("1234")
    MainWindow._refresh_action_states(window)
    assert "PIN on this device" in window.vault_unlock_source_label.text()


def test_run_enroll_vault_pin_first_time_sets_local_only_message(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.vault_pin_input.setText("1234")

    MainWindow.run_enroll_vault_pin(window)

    assert "PIN saved for this device." in window.status_label.text()
    assert "local to this desktop and is not synced elsewhere" in window.status_label.text()
    assert window.desktop_service.local_pin_bootstrap_status() == "current_account"


def test_run_enroll_vault_pin_rejects_change_without_confirm(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.desktop_service.enroll_local_pin_bootstrap(pin="1234")
    window.vault_pin_input.setText("5678")

    MainWindow.run_enroll_vault_pin(window)

    assert "Type CONFIRM before changing or replacing the device PIN." in window.status_label.text()


def test_run_remove_vault_pin_with_confirm_clears_local_bootstrap(qapp, tmp_path: Path) -> None:
    window = make_window_harness(tmp_path)
    window.desktop_service.set_session_vault_master_key(VALID_MASTER_KEY_B64)
    window.desktop_service.enroll_local_pin_bootstrap(pin="1234")
    window.pin_confirmation_input.setText("CONFIRM")

    MainWindow.run_remove_vault_pin(window)

    assert window.desktop_service.local_pin_bootstrap_status() == "none"
    assert "Only this desktop was affected" in window.status_label.text()
