from __future__ import annotations

import json


def _json_text(value) -> str:
    return json.dumps(value, indent=2)


def _shorten(value: str, limit: int = 24) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1]}…"


def _append_local_decrypt_sections(lines: list[str], item: dict) -> None:
    has_plaintext = "plaintext_metadata" in item or "plaintext_payload" in item
    has_error = bool(item.get("decryption_error"))

    if not has_plaintext and not has_error:
        return

    lines.extend(
        [
            "Local decrypt status:",
            f"{'Unavailable: ' + str(item.get('decryption_error')) if has_error else 'Available'}",
            "",
        ]
    )

    if has_plaintext:
        lines.extend(
            [
                "Plaintext metadata:",
                _json_text(item.get("plaintext_metadata")),
                "",
                "Plaintext payload:",
                _json_text(item.get("plaintext_payload")),
                "",
            ]
        )


def _append_plaintext_pairs(lines: list[str], payload: dict | None, *, skip: set[str] | None = None) -> None:
    data = payload or {}
    ignored = skip or set()
    extras = [
        (str(key), value)
        for key, value in data.items()
        if key not in ignored and value not in (None, "", [], {})
    ]
    if not extras:
        return

    lines.append("Details:")
    for key, value in extras:
        lines.append(f"{key.replace('_', ' ').title()}: {value}")
    lines.append("")


def credential_list_label(item: dict) -> str:
    app_name = item.get("plaintext_app_name") or item.get("credential_id", "-")
    username = item.get("plaintext_username") or ""
    primary = _shorten(str(app_name), 28) or "-"
    secondary = _shorten(str(username), 28)
    if secondary:
        return f"{primary} · {secondary}"
    return primary


def note_list_label(item: dict) -> str:
    title = item.get("plaintext_title") or item.get("note_id", "-")
    return (
        f"{title}"
        f" | {item.get('note_type', '-')}"
        f" | {item.get('state', '-')}"
        f" | v{item.get('current_version', '-')}"
    )


def file_list_label(item: dict) -> str:
    filename = item.get("plaintext_filename") or item.get("file_id", "-")
    size = item.get("plaintext_size_bytes")
    size_text = f"{size} B" if size is not None else "size unknown"
    return (
        f"{filename}"
        f" | {size_text}"
        f" | {item.get('state', '-')}"
        f" | v{item.get('current_version', '-')}"
    )


def format_credentials_items(items: list[dict]) -> str:
    if not items:
        return "Credentials loaded successfully.\nCount: 0\n\nNo credentials found."

    lines = [
        "Credentials loaded successfully.",
        f"Count: {len(items)}",
        "",
    ]

    for index, item in enumerate(items, start=1):
        lines.extend(
            [
                f"[{index}] Credential",
                f"  App: {item.get('plaintext_app_name', '-')}",
                f"  Username: {item.get('plaintext_username', '-')}",
                f"  ID: {item.get('credential_id', '-')}",
                f"  State: {item.get('state', '-')}",
                f"  Current version: {item.get('current_version', '-')}",
                f"  Updated at: {item.get('updated_at', '-')}",
                "",
            ]
        )

    return "\n".join(lines).rstrip()


def format_notes_items(items: list[dict]) -> str:
    if not items:
        return "Notes loaded successfully.\nCount: 0\n\nNo notes found."

    lines = [
        "Notes loaded successfully.",
        f"Count: {len(items)}",
        "",
    ]

    for index, item in enumerate(items, start=1):
        lines.extend(
            [
                f"[{index}] Note",
                f"  Title: {item.get('plaintext_title', '-')}",
                f"  ID: {item.get('note_id', '-')}",
                f"  Type: {item.get('note_type', '-')}",
                f"  State: {item.get('state', '-')}",
                f"  Current version: {item.get('current_version', '-')}",
                f"  Updated at: {item.get('updated_at', '-')}",
                "",
            ]
        )

    return "\n".join(lines).rstrip()


def format_files_items(items: list[dict]) -> str:
    if not items:
        return "Files loaded successfully.\nCount: 0\n\nNo files found."

    lines = [
        "Files loaded successfully.",
        f"Count: {len(items)}",
        "",
    ]

    for index, item in enumerate(items, start=1):
        lines.extend(
            [
                f"[{index}] File",
                f"  Name: {item.get('plaintext_filename', '-')}",
                f"  Size: {item.get('plaintext_size_bytes', '-')}",
                f"  ID: {item.get('file_id', '-')}",
                f"  State: {item.get('state', '-')}",
                f"  Current version: {item.get('current_version', '-')}",
                f"  Updated at: {item.get('updated_at', '-')}",
                "",
            ]
        )

    return "\n".join(lines).rstrip()


def format_credential_detail(item: dict) -> str:
    payload = item.get("plaintext_payload") or {}
    metadata = item.get("plaintext_metadata") or {}
    username = item.get("plaintext_username") or payload.get("username") or "-"
    lines = [
        "Credential detail loaded successfully.",
        "",
        f"App: {item.get('plaintext_app_name', '-')}",
        f"Username: {username}",
        f"State: {item.get('state', '-')}",
        "",
    ]

    label = metadata.get("label")
    if label and label != item.get("plaintext_app_name"):
        lines.append(f"Label: {label}")
    if payload.get("url"):
        lines.append(f"URL: {payload.get('url')}")
    if payload.get("secret"):
        lines.append(f"Secret: {payload.get('secret')}")
    if len(lines) > 5:
        lines.append("")

    if item.get("decryption_error"):
        lines.extend(
            [
                "Unlock vault to view decrypted content.",
                f"Reason: {item.get('decryption_error')}",
                "",
            ]
        )
        return "\n".join(lines).rstrip()

    _append_plaintext_pairs(lines, payload, skip={"username", "url", "secret"})
    return "\n".join(lines).rstrip()


def format_note_detail(item: dict) -> str:
    payload = item.get("plaintext_payload") or {}
    lines = [
        "Note detail loaded successfully.",
        "",
        f"Title: {item.get('plaintext_title', '-')}",
        f"Type: {item.get('note_type', '-')}",
        f"State: {item.get('state', '-')}",
        "",
    ]

    if item.get("decryption_error"):
        lines.extend(
            [
                "Unlock vault to view decrypted content.",
                f"Reason: {item.get('decryption_error')}",
                "",
            ]
        )
        return "\n".join(lines).rstrip()

    body = payload.get("content") or payload.get("body") or payload.get("text")
    if body:
        lines.extend(
            [
                "Content:",
                str(body),
                "",
            ]
        )
    _append_plaintext_pairs(lines, payload, skip={"content", "body", "text"})
    return "\n".join(lines).rstrip()


def format_file_detail(item: dict) -> str:
    return (
        "File detail loaded successfully.\n\n"
        f"Name: {item.get('plaintext_filename', '-')}\n"
        f"Size: {item.get('plaintext_size_bytes', '-')}\n"
        f"State: {item.get('state', '-')}\n"
        f"Current version: {item.get('current_version', '-')}"
    )
