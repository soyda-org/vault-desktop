from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication

from app.ui.signup_dialog import SignupDialog


@pytest.fixture
def app_fixture() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_signup_dialog_rejects_mismatched_passwords(app_fixture) -> None:
    dialog = SignupDialog(api_base_url="http://127.0.0.1:8000")
    dialog.identifier_input.setText("alice")
    dialog.password_input.setText("one")
    dialog.password_confirm_input.setText("two")

    dialog.run_register()

    assert "does not match" in dialog.info_label.text()


def test_signup_dialog_accepts_after_recovery_ack(monkeypatch, app_fixture) -> None:
    monkeypatch.setattr("app.ui.signup_dialog.show_recovery_key_dialog", lambda parent, key: True)

    def fake_start(self, **kwargs):
        self._on_signup_succeeded({"recovery_key_b64": "cmVjb3Y="})

    monkeypatch.setattr(SignupDialog, "_start_signup_worker", fake_start)

    dialog = SignupDialog(api_base_url="http://127.0.0.1:8000")
    dialog.identifier_input.setText("alice")
    dialog.password_input.setText("pass123")
    dialog.password_confirm_input.setText("pass123")

    dialog.run_register()

    assert dialog.result() == SignupDialog.DialogCode.Accepted
    assert dialog.registered_identifier == "alice"


def test_signup_dialog_shows_error_without_freezing(monkeypatch, app_fixture) -> None:
    def fake_start(self, **kwargs):
        self._on_signup_failed("backend unavailable")

    monkeypatch.setattr(SignupDialog, "_start_signup_worker", fake_start)

    dialog = SignupDialog(api_base_url="http://127.0.0.1:8000")
    dialog.identifier_input.setText("alice")
    dialog.password_input.setText("pass123")
    dialog.password_confirm_input.setText("pass123")

    dialog.run_register()

    assert "backend unavailable" in dialog.info_label.text()
    assert dialog.create_button.isEnabled()


def test_signup_dialog_prefills_detected_device_defaults(monkeypatch, app_fixture) -> None:
    monkeypatch.setattr(
        "app.ui.signup_dialog.detect_local_device_defaults",
        lambda: ("studio-box", "linux"),
    )

    dialog = SignupDialog(api_base_url="http://127.0.0.1:8000")

    assert dialog.device_name_input.text() == "studio-box"
    assert dialog.platform_input.text() == "linux"
    assert dialog.device_name_input.isReadOnly()
    assert dialog.platform_input.isReadOnly()
    assert dialog.device_name_input.placeholderText() == "device name - automatically filled"
    assert dialog.platform_input.placeholderText() == "platform - automatically filled"
    assert dialog.device_name_input.property("autoFilled") is True
    assert dialog.platform_input.property("autoFilled") is True
