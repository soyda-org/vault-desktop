from __future__ import annotations

from PySide6.QtWidgets import (
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.core.config import DesktopSettings
from app.services.api_client import VaultApiClient


class MainWindow(QMainWindow):
    def __init__(self, settings: DesktopSettings) -> None:
        super().__init__()
        self.settings = settings
        self.api_client = VaultApiClient(settings.api_base_url)

        self.setWindowTitle(settings.app_name)
        self.resize(640, 240)

        self.status_label = QLabel("Press 'Probe API' to test backend connectivity.")
        self.status_label.setWordWrap(True)

        self.probe_button = QPushButton("Probe API")
        self.probe_button.clicked.connect(self.run_probe)

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"App: {settings.app_name}"))
        layout.addWidget(QLabel(f"Environment: {settings.environment}"))
        layout.addWidget(QLabel(f"API base URL: {settings.api_base_url}"))
        layout.addWidget(self.probe_button)
        layout.addWidget(self.status_label)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def run_probe(self) -> None:
        result = self.api_client.probe()

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
