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
    monkeypatch.setattr(
        "app.ui.signup_dialog.register_with_recovery",
        lambda **kwargs: {"user_id": "user_001", "recovery_key_b64": "cmVjb3Y="},
    )
    monkeypatch.setattr("app.ui.signup_dialog.show_recovery_key_dialog", lambda parent, key: True)

    dialog = SignupDialog(api_base_url="http://127.0.0.1:8000")
    dialog.identifier_input.setText("alice")
    dialog.password_input.setText("pass123")
    dialog.password_confirm_input.setText("pass123")

    dialog.run_register()

    assert dialog.result() == SignupDialog.DialogCode.Accepted
    assert dialog.registered_identifier == "alice"
