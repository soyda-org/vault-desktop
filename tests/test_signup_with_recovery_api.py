from __future__ import annotations

from types import SimpleNamespace

import app.services.signup_with_recovery_api as module


def test_register_with_recovery_bootstraps_vault_and_posts_register_payload(monkeypatch) -> None:
    bootstrap = SimpleNamespace(
        recovery_key_b64="cmVjb3Y=",
        persisted=SimpleNamespace(
            unlock_salt_b64="c2FsdA==",
            unlock_kdf_params={"scheme": "argon2id"},
            wrapped_vault_root_key={"wrap_scheme": "aes256-kw", "wrapped_key_b64": "YWJj"},
            recovery_wrapped_vault_root_key={"wrap_scheme": "aes256-kw", "wrapped_key_b64": "ZGVm"},
        ),
    )
    calls = []

    monkeypatch.setattr(module, "bootstrap_new_vault", lambda **kwargs: bootstrap)

    def fake_post_json(*, base_url, path, payload, expected_statuses):
        calls.append((path, payload, expected_statuses))
        return {"user_id": "user_001", "device_id": "dev_001"}

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
    assert calls[0][1]["identifier"] == "alice"
    assert calls[0][1]["password"] == "pass123"
    assert calls[0][1]["unlock_salt_b64"] == "c2FsdA=="
    assert calls[0][1]["wrapped_vault_root_key"]["wrap_scheme"] == "aes256-kw"
    assert calls[0][1]["recovery_wrapped_vault_root_key"]["wrapped_key_b64"] == "ZGVm"


def test_register_with_recovery_rejects_missing_recovery_key(monkeypatch) -> None:
    bootstrap = SimpleNamespace(
        recovery_key_b64=None,
        persisted=SimpleNamespace(
            unlock_salt_b64="c2FsdA==",
            unlock_kdf_params={"scheme": "argon2id"},
            wrapped_vault_root_key={"wrap_scheme": "aes256-kw", "wrapped_key_b64": "YWJj"},
            recovery_wrapped_vault_root_key=None,
        ),
    )
    monkeypatch.setattr(module, "bootstrap_new_vault", lambda **kwargs: bootstrap)

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


def test_register_with_recovery_surfaces_bootstrap_failure(monkeypatch) -> None:
    def fail_bootstrap(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(module, "bootstrap_new_vault", fail_bootstrap)

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
        assert "Local vault bootstrap failed" in str(exc)
