from __future__ import annotations

import app.services.signup_with_recovery_api as module


def test_register_with_recovery_uses_reset_endpoint(monkeypatch) -> None:
    calls = []

    def fake_post_json(*, base_url, path, payload, expected_statuses):
        calls.append((path, payload))
        if path == "/api/v1/auth/register":
            return {"ok": True}
        if path == "/api/v1/auth/recovery/reset":
            return {"user_id": "user_001", "recovery_key_b64": "cmVjb3Y="}
        raise AssertionError(path)

    monkeypatch.setattr(module, "_post_json", fake_post_json)

    result = module.register_with_recovery(
        base_url="http://127.0.0.1:8000",
        identifier="alice",
        password="pass123",
        device_name="vault-desktop-dev",
        platform="linux",
    )

    assert result["recovery_key_b64"] == "cmVjb3Y="
    assert calls[0][0] == "/api/v1/auth/register"
    assert calls[1][0] == "/api/v1/auth/recovery/reset"
    assert calls[1][1] == {"identifier": "alice", "unlock_passphrase": "pass123"}


def test_register_with_recovery_raises_on_missing_recovery_key(monkeypatch) -> None:
    def fake_post_json(*, base_url, path, payload, expected_statuses):
        if path == "/api/v1/auth/register":
            return {"ok": True}
        return {"user_id": "user_001"}

    monkeypatch.setattr(module, "_post_json", fake_post_json)

    try:
        module.register_with_recovery(
            base_url="http://127.0.0.1:8000",
            identifier="alice",
            password="pass123",
            device_name="vault-desktop-dev",
            platform="linux",
        )
        assert False, "Expected SignupWithRecoveryError"
    except module.SignupWithRecoveryError as exc:
        assert "recovery_key_b64" in str(exc)
