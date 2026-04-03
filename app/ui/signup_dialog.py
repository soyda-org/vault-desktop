from __future__ import annotations

from PySide6.QtCore import QThread
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from app.core.local_settings import detect_local_device_defaults
from app.services.signup_with_recovery_api import SignupWithRecoveryError, register_with_recovery
from app.ui.network_action_worker import NetworkActionWorker
from app.ui.recovery_key_dialog import show_recovery_key_dialog


class SignupDialog(QDialog):
    def __init__(
        self,
        *,
        api_base_url: str,
        identifier: str = "",
        device_name: str | None = None,
        platform: str | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        default_device_name, default_platform = detect_local_device_defaults()
        self.api_base_url = api_base_url
        self.registered_identifier = ""
        self._signup_thread: QThread | None = None
        self._signup_worker: NetworkActionWorker | None = None
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
        self.device_name_input.setText(device_name or default_device_name)
        self.device_name_input.setReadOnly(True)
        self.device_name_input.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        form.addRow("Device name", self.device_name_input)

        self.platform_input = QLineEdit()
        self.platform_input.setText(platform or default_platform)
        self.platform_input.setReadOnly(True)
        self.platform_input.setFocusPolicy(Qt.FocusPolicy.NoFocus)
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

    def _set_busy(self, busy: bool) -> None:
        self.identifier_input.setEnabled(not busy)
        self.password_input.setEnabled(not busy)
        self.password_confirm_input.setEnabled(not busy)
        self.device_name_input.setEnabled(not busy)
        self.platform_input.setEnabled(not busy)
        self.create_button.setEnabled(not busy)
        self.cancel_button.setEnabled(not busy)

    def _cleanup_signup_worker(self) -> None:
        self._signup_worker = None
        self._signup_thread = None
        self._set_busy(False)

    def _on_signup_failed(self, message: str) -> None:
        self.info_label.setText(message)

    def _on_signup_succeeded(self, result: dict) -> None:
        acknowledged = show_recovery_key_dialog(self, result["recovery_key_b64"])
        if not acknowledged:
            self.info_label.setText(
                "Registration succeeded, but the recovery key dialog was not completed. "
                "The key was shown once and is not accessible again."
            )
            return

        self.registered_identifier = self.identifier_input.text().strip()
        self.accept()

    def _start_signup_worker(self, *, identifier: str, password: str, device_name: str, platform: str) -> None:
        if self._signup_thread is not None and self._signup_thread.isRunning():
            self.info_label.setText("A signup request is already running.")
            return

        self.info_label.setText("Creating account...")
        self._set_busy(True)

        action = lambda: register_with_recovery(
            base_url=self.api_base_url,
            identifier=identifier,
            password=password,
            device_name=device_name,
            platform=platform,
        )

        thread = QThread(self)
        worker = NetworkActionWorker(action)
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.succeeded.connect(self._on_signup_succeeded)
        worker.failed.connect(self._on_signup_failed)
        worker.succeeded.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.succeeded.connect(lambda _result: self._cleanup_signup_worker())
        worker.failed.connect(lambda _message: self._cleanup_signup_worker())
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        self._signup_thread = thread
        self._signup_worker = worker
        thread.start()

    def run_register(self) -> None:
        default_device_name, default_platform = detect_local_device_defaults()
        error = self._validate_inputs()
        if error:
            self.info_label.setText(error)
            return

        try:
            self._start_signup_worker(
                identifier=self.identifier_input.text().strip(),
                password=self.password_input.text(),
                device_name=self.device_name_input.text().strip() or default_device_name,
                platform=self.platform_input.text().strip() or default_platform,
            )
        except SignupWithRecoveryError as exc:
            self.info_label.setText(str(exc))
            return
