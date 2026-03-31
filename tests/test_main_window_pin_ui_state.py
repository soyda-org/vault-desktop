import os
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QListWidget, QPushButton, QWidget

from app.core.pin_bootstrap import LocalPinBootstrapStore
from app.services.desktop_service import VaultDesktopService
from app.ui.main_window import MainWindow
from vault_crypto.encoding import b64encode_bytes
from vault_crypto.vault_setup import bootstrap_new_vault

VALID_MASTER_KEY_B64 = "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s="


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

    window.vault_pin_input = QLineEdit()
    window.pin_confirmation_input = QLineEdit()
    window.recovery_key_b64_input = QLineEdit()
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
    window.unlock_with_recovery_key_button = QPushButton()
    window.clear_vault_key_button = QPushButton()

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
    window.refresh_session_label = lambda: None
    window._refresh_after_vault_unlock = lambda: None
    window._refresh_idle_policy = lambda: None

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
