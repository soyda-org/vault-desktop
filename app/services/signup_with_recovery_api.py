from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from vault_crypto.vault_setup import bootstrap_new_vault
except ModuleNotFoundError:
    sibling_src = Path(__file__).resolve().parents[3] / "vault-crypto" / "src"
    if sibling_src.exists() and str(sibling_src) not in sys.path:
        sys.path.append(str(sibling_src))
    from vault_crypto.vault_setup import bootstrap_new_vault


class SignupWithRecoveryError(RuntimeError):
    pass


def _extract_error_detail(raw_text: str) -> str:
    if not raw_text:
        return ""
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return raw_text.strip()
    if isinstance(data, dict):
        detail = data.get("detail")
        if isinstance(detail, str):
            return detail
        if isinstance(detail, list) and detail:
            return str(detail[0])
    return raw_text.strip()


def _post_json(
    *,
    base_url: str,
    path: str,
    payload: dict[str, Any],
    expected_statuses: tuple[int, ...] = (200,),
) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    url = base_url.rstrip("/") + path
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            status = getattr(response, "status", 200)
            raw = response.read().decode("utf-8")
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        detail = _extract_error_detail(raw)
        raise SignupWithRecoveryError(detail or f"HTTP {exc.code} calling {path}") from exc
    except URLError as exc:
        raise SignupWithRecoveryError(f"Cannot reach API at {base_url}: {exc.reason}") from exc

    if status not in expected_statuses:
        raise SignupWithRecoveryError(f"Unexpected HTTP {status} calling {path}")

    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SignupWithRecoveryError(f"Invalid JSON returned by {path}") from exc
    if not isinstance(data, dict):
        raise SignupWithRecoveryError(f"Unexpected response shape from {path}")
    return data


def register_with_recovery(
    *,
    base_url: str,
    identifier: str,
    password: str,
    device_name: str,
    platform: str,
) -> dict[str, Any]:
    try:
        bootstrap = bootstrap_new_vault(
            unlock_passphrase=password,
            include_recovery_key=True,
        )
    except Exception as exc:
        raise SignupWithRecoveryError(f"Local vault bootstrap failed: {exc}") from exc

    recovery_key_b64 = getattr(bootstrap, "recovery_key_b64", None)
    if not recovery_key_b64:
        raise SignupWithRecoveryError("Local vault bootstrap did not return recovery_key_b64.")

    persisted = getattr(bootstrap, "persisted", None)
    if persisted is None:
        raise SignupWithRecoveryError("Local vault bootstrap did not return persisted material.")

    payload = {
        "identifier": identifier,
        "password": password,
        "device_name": device_name,
        "platform": platform,
        "unlock_salt_b64": persisted.unlock_salt_b64,
        "unlock_kdf_params": persisted.unlock_kdf_params,
        "wrapped_vault_root_key": persisted.wrapped_vault_root_key,
        "recovery_wrapped_vault_root_key": persisted.recovery_wrapped_vault_root_key,
    }

    register_response = _post_json(
        base_url=base_url,
        path="/api/v1/auth/register",
        payload=payload,
        expected_statuses=(200, 201),
    )
    register_response["recovery_key_b64"] = recovery_key_b64
    return register_response
