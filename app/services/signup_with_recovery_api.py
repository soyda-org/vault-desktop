from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


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


def _try_register(
    *,
    base_url: str,
    identifier: str,
    password: str,
    device_name: str,
    platform: str,
) -> None:
    attempts = [
        {
            "identifier": identifier,
            "password": password,
            "device_name": device_name,
            "platform": platform,
        },
        {
            "primary_identifier": identifier,
            "password": password,
            "device_name": device_name,
            "platform": platform,
        },
        {
            "identifier": identifier,
            "passphrase": password,
            "device_name": device_name,
            "platform": platform,
        },
    ]

    last_error: Exception | None = None
    for payload in attempts:
        try:
            _post_json(
                base_url=base_url,
                path="/api/v1/auth/register",
                payload=payload,
                expected_statuses=(200, 201),
            )
            return
        except SignupWithRecoveryError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise SignupWithRecoveryError("Registration failed for an unknown reason.")


def register_with_recovery(
    *,
    base_url: str,
    identifier: str,
    password: str,
    device_name: str,
    platform: str,
) -> dict[str, Any]:
    _try_register(
        base_url=base_url,
        identifier=identifier,
        password=password,
        device_name=device_name,
        platform=platform,
    )

    reset_response = _post_json(
        base_url=base_url,
        path="/api/v1/auth/recovery/reset",
        payload={
            "identifier": identifier,
            "unlock_passphrase": password,
        },
        expected_statuses=(200,),
    )

    if "recovery_key_b64" not in reset_response:
        raise SignupWithRecoveryError("Recovery reset response did not contain recovery_key_b64.")

    return reset_response
