from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QObject, Signal


class NetworkActionWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, action: Callable[[], Any]) -> None:
        super().__init__()
        self._action = action

    def run(self) -> None:
        try:
            result = self._action()
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(result)
