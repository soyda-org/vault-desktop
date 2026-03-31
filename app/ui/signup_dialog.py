from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from app.services.signup_with_recovery_api import SignupWithRecoveryError, register_with_recovery
from app.ui.recovery_key_dialog import show_recovery_key_dialog


class SignupDialog(QDialog):
    def __init__(
        self,
        *,
        api_base_url: str,
        identifier: str = "",
        device_name: str = "vault-desktop-dev",
        platform: str = "linux",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.api_base_url = api_base_url
        self.registered_identifier = ""
        self.setWindowTitle("Sign Up / Create Vault")
        self.setModal(True)

        outer = QVBoxLayout(self)
        form = QFormLayout()

        self.identifier_input = QLineEdit()
        self.identifier_input.setText(identifier)
        form.addRow("Identifier", self.identifier_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        form.addRow("Password", self.password_input)

        self.password_confirm_input = QLineEdit()
        self.password_confirm_input.setEchoMode(QLineEdit.Password)
        form.addRow("Confirm password", self.password_confirm_input)

        self.device_name_input = QLineEdit()
        self.device_name_input.setText(device_name)
        form.addRow("Device name", self.device_name_input)

        self.platform_input = QLineEdit()
        self.platform_input.setText(platform)
        form.addRow("Platform", self.platform_input)

        outer.addLayout(form)

        self.info_label = QLabel(
            "Create a new account and vault. The recovery key will be shown once and must be saved immediately."
        )
        self.info_label.setWordWrap(True)
        outer.addWidget(self.info_label)

        row = QHBoxLayout()
        row.addStretch(1)

        self.create_button = QPushButton("Create Account")
        self.create_button.clicked.connect(self.run_register)
        row.addWidget(self.create_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        row.addWidget(self.cancel_button)

        outer.addLayout(row)

    def _validate_inputs(self) -> str | None:
        identifier = self.identifier_input.text().strip()
        password = self.password_input.text()
        confirm = self.password_confirm_input.text()
        if not identifier:
            return "Identifier is required."
        if not password:
            return "Password is required."
        if password != confirm:
            return "Password confirmation does not match."
        return None

    def run_register(self) -> None:
        error = self._validate_inputs()
        if error:
            self.info_label.setText(error)
            return

        try:
            result = register_with_recovery(
                base_url=self.api_base_url,
                identifier=self.identifier_input.text().strip(),
                password=self.password_input.text(),
                device_name=self.device_name_input.text().strip() or "vault-desktop-dev",
                platform=self.platform_input.text().strip() or "linux",
            )
        except SignupWithRecoveryError as exc:
            self.info_label.setText(str(exc))
            return

        acknowledged = show_recovery_key_dialog(self, result["recovery_key_b64"])
        if not acknowledged:
            self.info_label.setText(
                "Registration succeeded, but the recovery key dialog was not completed. "
                "The key was shown once and is not accessible again."
            )
            return

        self.registered_identifier = self.identifier_input.text().strip()
        self.accept()
