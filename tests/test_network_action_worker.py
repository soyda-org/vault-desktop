from __future__ import annotations

from app.ui.network_action_worker import NetworkActionWorker


def test_network_action_worker_emits_success_result() -> None:
    observed: list[object] = []
    worker = NetworkActionWorker(lambda: {"ok": True})
    worker.succeeded.connect(observed.append)

    worker.run()

    assert observed == [{"ok": True}]


def test_network_action_worker_emits_failure_message() -> None:
    observed: list[str] = []

    def boom() -> object:
        raise RuntimeError("probe failed")

    worker = NetworkActionWorker(boom)
    worker.failed.connect(observed.append)

    worker.run()

    assert observed == ["probe failed"]
