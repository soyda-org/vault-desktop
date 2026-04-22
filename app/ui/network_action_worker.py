from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QThread, Signal


class NetworkActionWorker(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, action: Callable[[], Any], parent=None) -> None:
        super().__init__(parent)
        self._action = action

    def run(self) -> None:  # type: ignore[override]
        try:
            result = self._action()
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(result)
