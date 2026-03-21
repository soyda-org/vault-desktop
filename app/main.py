from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from app.core.config import get_settings
from app.ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    settings = get_settings()
    window = MainWindow(settings)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
