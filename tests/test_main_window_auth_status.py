from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QShowEvent
from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QListWidget, QPushButton

from app.core.config import get_settings
from app.core.local_settings import PersistedUiSettings
from app.core.session import DesktopSession
from app.services.api_client import ObjectListResult
from app.ui.main_window import MainWindow

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture
def app_fixture() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_handle_login_result_does_not_show_access_token_preview(app_fixture) -> None:
    session = SimpleNamespace(
        user_id="user_1",
        device_id="device_1",
        session_id="session_1",
        token_type="bearer",
        access_token="access-token-1",
    )
    desktop_service = SimpleNamespace(
        current_session=lambda: session,
    )
    window = SimpleNamespace(
        desktop_service=desktop_service,
        status_label=QLabel(),
        recovery_key_b64_input=QLineEdit(),
        current_screen="system",
        current_vault_panel="workspace",
        refresh_session_label=lambda: None,
        _is_vault_unlocked=lambda: False,
        _clear_sensitive_views_for_locked_vault=lambda: None,
        _refresh_action_states=lambda: None,
        _refresh_idle_policy=lambda: None,
        _save_ui_preferences=lambda: None,
    )

    MainWindow._handle_login_result(window, SimpleNamespace(error=None))

    assert "Login succeeded." in window.status_label.text()
    assert "Token type: bearer" in window.status_label.text()
    assert "Access token preview" not in window.status_label.text()
    assert window.current_screen == "vault"
    assert window.current_vault_panel == "access"


def test_refresh_system_state_indicators_reflect_probe_and_session(app_fixture) -> None:
    desktop_service = SimpleNamespace(
        is_authenticated=lambda: True,
    )
    window = SimpleNamespace(
        desktop_service=desktop_service,
        _last_probe_result=SimpleNamespace(
            error=None,
            project_name="vault-api",
            version="0.1.0",
            environment="dev",
        ),
        connection_state_label=QLabel(),
        session_state_label=QLabel(),
        vault_state_label=QLabel(),
        api_details_label=QLabel(),
        api_client=SimpleNamespace(base_url="http://127.0.0.1:8000"),
        _is_vault_unlocked=lambda: False,
        probe_button=QPushButton(),
        login_button=QPushButton(),
        _set_badge_state=lambda label, level: None,
        _set_button_tone=lambda button, tone: None,
    )

    MainWindow._refresh_system_state_indicators(window)

    assert window.connection_state_label.text() == "API ok."
    assert window.session_state_label.text() == "Session active."
    assert window.vault_state_label.text() == "Vault locked."
    assert "Project: vault-api" in window.api_details_label.text()
    assert "API: http://127.0.0.1:8000" in window.api_details_label.text()


def test_refresh_system_state_indicators_hides_api_before_probe_or_login(app_fixture) -> None:
    desktop_service = SimpleNamespace(
        is_authenticated=lambda: False,
    )
    window = SimpleNamespace(
        desktop_service=desktop_service,
        _last_probe_result=None,
        connection_state_label=QLabel(),
        session_state_label=QLabel(),
        vault_state_label=QLabel(),
        api_details_label=QLabel(),
        api_client=SimpleNamespace(base_url="http://127.0.0.1:8000"),
        _is_vault_unlocked=lambda: False,
        probe_button=QPushButton(),
        login_button=QPushButton(),
        _set_badge_state=lambda label, level: None,
        _set_button_tone=lambda button, tone: None,
    )

    MainWindow._refresh_system_state_indicators(window)

    assert window.api_details_label.text() == ""


def test_main_window_device_fields_are_read_only(app_fixture) -> None:
    window = MainWindow(get_settings())

    assert window.minimumWidth() == 600
    assert window.minimumHeight() == 400
    assert window.identifier_input.property("ghostField") is True
    assert window.password_input.property("ghostField") is True
    assert window.device_name_input.isReadOnly()
    assert window.platform_input.isReadOnly()
    assert window.device_name_input.placeholderText() == "device name - automatically filled"
    assert window.platform_input.placeholderText() == "platform - automatically filled"
    assert window.device_name_input.property("autoFilled") is True
    assert window.platform_input.property("autoFilled") is True
    assert window.device_name_input.property("ghostField") is True
    assert window.platform_input.property("ghostField") is True
    assert window.identifier_input.alignment() == Qt.AlignmentFlag.AlignCenter
    assert window.password_input.alignment() == Qt.AlignmentFlag.AlignCenter
    assert window.device_name_input.alignment() == Qt.AlignmentFlag.AlignCenter
    assert window.platform_input.alignment() == Qt.AlignmentFlag.AlignCenter


def test_theme_toggle_button_text_tracks_current_theme(app_fixture) -> None:
    window = MainWindow(get_settings())

    window.current_theme = "dark"
    window.resize(1180, 780)
    window._apply_theme()
    assert window.theme_toggle_button.text() == "Dark"

    window.current_theme = "light"
    window.resize(1180, 780)
    window._apply_theme()
    assert window.theme_toggle_button.text() == "Light"


def test_shared_navbar_compacts_to_single_letters_when_window_is_narrow(app_fixture) -> None:
    window = MainWindow(get_settings())

    window.current_theme = "dark"
    window.resize(720, 780)
    window._refresh_navbar_labels()

    assert window.theme_toggle_button.text() == "D"
    assert window.nav_generator_button.text() == "G"
    assert window.system_service_tab_button.text() == "A"
    assert window.nav_vault_button.text() == "V"


def test_main_window_restores_persisted_size(app_fixture, monkeypatch) -> None:
    from app.ui import main_window as main_window_module

    monkeypatch.setattr(
        main_window_module.LocalSettingsStore,
        "load",
        lambda self: PersistedUiSettings(window_width=910, window_height=650),
    )

    window = MainWindow(get_settings())

    assert window.width() == 910
    assert window.height() == 650


def test_main_window_restores_persisted_position(app_fixture, monkeypatch) -> None:
    from app.ui import main_window as main_window_module

    monkeypatch.setattr(
        main_window_module.LocalSettingsStore,
        "load",
        lambda self: PersistedUiSettings(window_x=120, window_y=90),
    )

    window = MainWindow(get_settings())

    assert window.x() == 120
    assert window.y() == 90


def test_main_window_restores_persisted_position_even_with_geometry_blob(
    app_fixture, monkeypatch
) -> None:
    from app.ui import main_window as main_window_module

    monkeypatch.setattr(
        main_window_module.LocalSettingsStore,
        "load",
        lambda self: PersistedUiSettings(
            window_geometry_b64="ZmFrZS1nZW9tZXRyeQ==",
            window_x=140,
            window_y=110,
        ),
    )

    window = MainWindow(get_settings())

    assert window.x() == 140
    assert window.y() == 110


def test_show_event_reapplies_pending_window_position_with_delayed_retry(
    app_fixture, monkeypatch
) -> None:
    from app.ui import main_window as main_window_module

    scheduled_delays: list[int] = []

    def fake_single_shot(delay: int, callback) -> None:
        scheduled_delays.append(delay)
        callback()

    monkeypatch.setattr(main_window_module.QTimer, "singleShot", fake_single_shot)

    window = MainWindow(get_settings())
    window._pending_window_position = (160, 130)

    event = QShowEvent()
    window.showEvent(event)

    assert scheduled_delays == [0, 75]
    assert window.x() == 160
    assert window.y() == 130
    assert window._pending_window_position is None


def test_quick_crypto_passphrase_field_follows_method_mode(app_fixture) -> None:
    window = MainWindow(get_settings())

    window.quick_crypto_method_select.setCurrentIndex(
        window.quick_crypto_method_select.findData("base64")
    )
    window._refresh_quick_crypto_method_state()
    assert window.quick_crypto_passphrase_input.isReadOnly()
    assert window.quick_crypto_passphrase_input.placeholderText() == "No passphrase needed"
    assert "no secrecy" in window.quick_crypto_help_button.toolTip().lower()

    window.quick_crypto_method_select.setCurrentIndex(
        window.quick_crypto_method_select.findData("caesar-shift")
    )
    window._refresh_quick_crypto_method_state()
    assert not window.quick_crypto_passphrase_input.isReadOnly()
    assert (
        window.quick_crypto_passphrase_input.placeholderText()
        == "Optional passphrase / shift seed"
    )
    caesar_tooltip = window.quick_crypto_help_button.toolTip().lower()
    assert "default shift" in caesar_tooltip
    assert "obfuscation" in caesar_tooltip

    window.quick_crypto_method_select.setCurrentIndex(
        window.quick_crypto_method_select.findData("aes-256-gcm")
    )
    window._refresh_quick_crypto_method_state()
    assert not window.quick_crypto_passphrase_input.isReadOnly()
    assert window.quick_crypto_passphrase_input.placeholderText() == "Passphrase required"
    assert "authenticated encryption" in window.quick_crypto_help_button.toolTip().lower()


def test_vault_pin_field_keeps_large_rendered_size_when_empty_or_typed(app_fixture) -> None:
    window = MainWindow(get_settings())

    window.vault_pin_input.clear()
    window._refresh_vault_pin_field_style()
    assert "font-size: 64px;" in window.vault_pin_input.styleSheet()

    window.vault_pin_input.setText("1234")
    window._refresh_vault_pin_field_style()
    assert "font-size: 64px;" in window.vault_pin_input.styleSheet()


def test_new_vault_pin_field_tracks_validity_state(app_fixture) -> None:
    window = MainWindow(get_settings())
    assert window.new_vault_pin_input.property("newVaultPinField") is True

    window.new_vault_pin_input.clear()
    window._refresh_new_vault_pin_field_state()
    assert window.new_vault_pin_input.property("pinValidity") == "idle"

    window.new_vault_pin_input.setText("123")
    window._refresh_new_vault_pin_field_state()
    assert window.new_vault_pin_input.property("pinValidity") == "invalid"

    window.new_vault_pin_input.setText("1234")
    window._refresh_new_vault_pin_field_state()
    assert window.new_vault_pin_input.property("pinValidity") == "valid"


def test_recovery_key_field_tracks_validity_state(app_fixture) -> None:
    window = MainWindow(get_settings())

    window.recovery_key_b64_input.clear()
    window._refresh_recovery_key_field_state()
    assert window.recovery_key_b64_input.property("recoveryValidity") == "idle"

    window.recovery_key_b64_input.setText("abcd")
    window._refresh_recovery_key_field_state()
    assert window.recovery_key_b64_input.property("recoveryValidity") == "idle"

    window._mark_recovery_key_valid()
    assert window.recovery_key_b64_input.property("recoveryValidity") == "valid"


def test_remember_session_checkbox_reflects_saved_preference(app_fixture, monkeypatch) -> None:
    from app.ui import main_window as main_window_module

    monkeypatch.setattr(
        main_window_module.LocalSettingsStore,
        "load",
        lambda self: PersistedUiSettings(
            remember_session=True,
            remembered_session={
                "identifier": "alice",
                "user_id": "user-1",
                "device_id": "device-1",
                "session_id": "session-1",
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "token_type": "bearer",
            },
        ),
    )
    window = MainWindow(get_settings())

    assert window.remember_session_checkbox.isChecked() is True
    assert window.desktop_service.is_authenticated() is True
    session = window.desktop_service.current_session()
    assert session is not None
    assert session.identifier == "alice"
    assert window.current_screen == "vault"
    assert window.current_vault_panel == "access"


def test_keep_vault_open_checkbox_reflects_saved_preference(app_fixture, monkeypatch) -> None:
    from app.ui import main_window as main_window_module

    monkeypatch.setattr(
        main_window_module.LocalSettingsStore,
        "load",
        lambda self: PersistedUiSettings(
            keep_vault_open=True,
        ),
    )
    window = MainWindow(get_settings())

    assert window.keep_vault_open_checkbox.isChecked() is True


def test_workspace_nav_buttons_follow_selected_tab(app_fixture) -> None:
    window = MainWindow(get_settings())

    window.tabs.setCurrentIndex(1)
    app_fixture.processEvents()

    assert window.workspace_notes_tab_button.property("segmentCurrent") is True
    assert window.workspace_credentials_tab_button.property("segmentCurrent") is False
    assert window.workspace_files_tab_button.property("segmentCurrent") is False


def test_credentials_filter_buttons_switch_visible_items(app_fixture) -> None:
    window = MainWindow(get_settings())
    window._render_credentials(
        ObjectListResult(
            items=[
                {
                    "credential_id": "cred_active",
                    "plaintext_app_name": "GitHub",
                    "plaintext_username": "alice",
                    "state": "active",
                    "current_version": 1,
                },
                {
                    "credential_id": "cred_deleted",
                    "plaintext_app_name": "Legacy",
                    "plaintext_username": "bob",
                    "state": "deleted",
                    "current_version": 2,
                },
            ]
        )
    )

    assert window.credentials_list.count() == 1
    assert "GitHub" in window.credentials_list.item(0).text()

    window.credentials_deleted_filter_button.click()
    app_fixture.processEvents()

    assert window.credentials_list.count() == 1
    assert "Legacy" in window.credentials_list.item(0).text()


def test_credential_detail_renders_readonly_fields_with_masked_password(app_fixture) -> None:
    window = MainWindow(get_settings())

    window._render_credential_detail_fields(
        {
            "credential_id": "cred_1",
            "state": "active",
            "plaintext_app_name": "GitHub",
            "plaintext_username": "alice@example.com",
            "plaintext_payload": {
                "secret": "s3cr3t",
                "url": "https://example.com",
            },
            "current_version": 1,
        }
    )

    assert window.credential_detail_stack.currentIndex() == 1
    assert window.credential_detail_name_input.text() == "GitHub"
    assert window.credential_detail_username_input.text() == "alice@example.com"
    assert window._credential_detail_password_plaintext == "s3cr3t"
    assert 8 <= len(window.credential_detail_password_input.text()) <= 14
    assert set(window.credential_detail_password_input.text()) == {"\u2022"}
    assert window.credential_detail_password_input.echoMode() == QLineEdit.EchoMode.Normal
    assert window.credential_detail_url_input.text() == "https://example.com"
    assert window.credential_detail_name_input.property("ghostField") is True
    assert window.credential_detail_url_input.property("ghostField") is True
    assert window.credential_detail_name_input.alignment() == Qt.AlignmentFlag.AlignCenter
    assert window.credential_detail_username_input.alignment() == Qt.AlignmentFlag.AlignCenter
    assert window.credential_detail_password_input.alignment() == Qt.AlignmentFlag.AlignCenter
    assert window.credential_detail_url_input.alignment() == Qt.AlignmentFlag.AlignCenter
    assert window.credential_detail_name_input.isReadOnly()
    assert window.credential_detail_username_input.isReadOnly()
    assert window.credential_detail_password_input.isReadOnly()
    assert window.toggle_credential_password_button.text() == "Show"


def test_credential_password_toggle_reveals_and_hides_value(app_fixture) -> None:
    window = MainWindow(get_settings())
    window._render_credential_detail_fields(
        {
            "state": "active",
            "plaintext_payload": {
                "secret": "s3cr3t",
            },
        }
    )

    assert window.toggle_credential_password_button.text() == "Show"
    hidden_display = window.credential_detail_password_input.text()
    assert 8 <= len(hidden_display) <= 14
    assert window.toggle_credential_password_button.text() == "Show"

    window.toggle_credential_password_button.click()

    assert window.credential_detail_password_input.text() == "s3cr3t"
    assert window.toggle_credential_password_button.text() == "Hide"

    window.toggle_credential_password_button.click()

    assert 8 <= len(window.credential_detail_password_input.text()) <= 14
    assert set(window.credential_detail_password_input.text()) == {"\u2022"}
    assert window.toggle_credential_password_button.text() == "Show"


def test_note_detail_renders_readonly_fields_with_focused_body_panel(app_fixture) -> None:
    window = MainWindow(get_settings())

    window._render_note_detail_fields(
        {
            "note_id": "note_1",
            "state": "active",
            "note_type": "note",
            "plaintext_title": "Daily plan",
            "plaintext_payload": {
                "content": "Buy milk\nShip patch",
            },
            "current_version": 3,
        }
    )

    assert window.note_detail_stack.currentIndex() == 1
    assert window.note_detail_title_input.text() == "Daily plan"
    assert window.note_detail_type_input.text() == "NOTE"
    assert window.note_detail_body_output.toPlainText() == "Buy milk\nShip patch"
    assert window.note_detail_title_input.property("ghostField") is True
    assert window.note_detail_title_input.alignment() == Qt.AlignmentFlag.AlignCenter
    assert window.note_detail_type_input.alignment() == Qt.AlignmentFlag.AlignCenter
    assert window.note_detail_title_input.isReadOnly()
    assert window.note_detail_type_input.isReadOnly()
    assert window.note_detail_body_output.isReadOnly()


def test_new_vault_pin_field_uses_default_rendered_size(app_fixture) -> None:
    window = MainWindow(get_settings())
    window.new_vault_pin_input.clear()
    window._refresh_new_vault_pin_field_state()
    assert window.new_vault_pin_input.styleSheet() == ""

    window.new_vault_pin_input.setText("1234")
    window._refresh_new_vault_pin_field_state()
    assert window.new_vault_pin_input.styleSheet() == ""


def test_main_window_auth_buttons_switch_visibility_with_session(app_fixture, monkeypatch) -> None:
    from app.ui import main_window as main_window_module

    monkeypatch.setattr(
        main_window_module.LocalSettingsStore,
        "load",
        lambda self: PersistedUiSettings(),
    )
    window = MainWindow(get_settings())
    window.show()
    app_fixture.processEvents()

    window._refresh_action_states()
    window._apply_screen_state()
    assert window.system_service_tab_button.text() == "Access"
    assert window.system_service_tab_button.property("segmentLevel") == "warning"
    assert window.nav_vault_button.property("navLevel") == "warning"
    assert not window.login_button.isHidden()
    assert not window.sign_up_button.isHidden()
    assert window.logout_button.isHidden()

    window.desktop_service.session_store.current = DesktopSession(
        identifier="alice",
        user_id="user_1",
        device_id="device_1",
        session_id="session_1",
        access_token="token",
        refresh_token="refresh-token",
        token_type="bearer",
    )
    window._refresh_action_states()
    window._apply_screen_state()
    app_fixture.processEvents()

    assert window.login_button.isHidden()
    assert window.sign_up_button.isHidden()
    assert not window.logout_button.isHidden()
    assert window.system_service_tab_button.property("segmentLevel") == "success"
    assert window.nav_vault_button.property("navLevel") == "warning"

    window.desktop_service.session_store.current = DesktopSession(
        identifier="alice",
        user_id="user_1",
        device_id="device_1",
        session_id="session_1",
        access_token="token",
        refresh_token="refresh-token",
        token_type="bearer",
        vault_master_key_b64="7U7C2e0z4A9Y2f1d9K8J3nS5mT6qP0wX1vB4cD7eF9g=",
    )
    window._refresh_action_states()
    window._apply_screen_state()
    app_fixture.processEvents()

    assert window.nav_vault_button.property("navLevel") == "success"


def test_run_login_rejects_empty_password_before_network(app_fixture) -> None:
    window = MainWindow(get_settings())
    window.identifier_input.setText("alice")
    window.password_input.clear()
    window.device_name_input.setText("device")
    window.platform_input.setText("linux")

    called = {"value": False}

    def fake_start_network_action(**kwargs):
        called["value"] = True

    window._start_network_action = fake_start_network_action  # type: ignore[assignment]

    window.run_login()

    assert called["value"] is False
    assert window.status_label.text() == "Login failed.\nError: Password is required."


def test_append_activity_log_keeps_newest_first_and_dedupes(app_fixture) -> None:
    window = SimpleNamespace(
        activity_log_list=QListWidget(),
        _last_activity_message="",
        _infer_status_severity=lambda message: MainWindow._infer_status_severity(SimpleNamespace(), message),
    )

    MainWindow._append_activity_log(window, "Login succeeded.")
    MainWindow._append_activity_log(window, "Login succeeded.")
    MainWindow._append_activity_log(window, "Vault locked.")

    assert window.activity_log_list.count() == 2
    assert "Vault locked." in window.activity_log_list.item(0).text()
    assert "Login succeeded." in window.activity_log_list.item(1).text()
