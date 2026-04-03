from __future__ import annotations

import json


def _json_text(value) -> str:
    return json.dumps(value, indent=2)


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


def credential_list_label(item: dict) -> str:
    app_name = item.get("plaintext_app_name") or item.get("credential_id", "-")
    username = item.get("plaintext_username") or "username unknown"
    return (
        f"{app_name}"
        f" | {username}"
        f" | {item.get('state', '-')}"
        f" | v{item.get('current_version', '-')}"
    )


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
    lines = [
        "Credential detail loaded successfully.",
        "",
        f"App: {item.get('plaintext_app_name', '-')}",
        f"Username: {item.get('plaintext_username', '-')}",
        f"ID: {item.get('credential_id', '-')}",
        f"User ID: {item.get('user_id', '-')}",
        f"State: {item.get('state', '-')}",
        f"Current version: {item.get('current_version', '-')}",
        f"Created by device ID: {item.get('created_by_device_id', '-')}",
        f"Created at: {item.get('created_at', '-')}",
        "",
    ]

    _append_local_decrypt_sections(lines, item)

    lines.extend(
        [
            "Encrypted metadata:",
            _json_text(item.get("encrypted_metadata")),
            "",
            "Encrypted payload:",
            _json_text(item.get("encrypted_payload")),
            "",
            "Encryption header:",
            _json_text(item.get("encryption_header")),
        ]
    )
    return "\n".join(lines)


def format_note_detail(item: dict) -> str:
    lines = [
        "Note detail loaded successfully.",
        "",
        f"Title: {item.get('plaintext_title', '-')}",
        f"ID: {item.get('note_id', '-')}",
        f"User ID: {item.get('user_id', '-')}",
        f"Type: {item.get('note_type', '-')}",
        f"State: {item.get('state', '-')}",
        f"Current version: {item.get('current_version', '-')}",
        f"Created by device ID: {item.get('created_by_device_id', '-')}",
        f"Created at: {item.get('created_at', '-')}",
        "",
    ]

    _append_local_decrypt_sections(lines, item)

    lines.extend(
        [
            "Encrypted metadata:",
            _json_text(item.get("encrypted_metadata")),
            "",
            "Encrypted payload:",
            _json_text(item.get("encrypted_payload")),
            "",
            "Encryption header:",
            _json_text(item.get("encryption_header")),
        ]
    )
    return "\n".join(lines)


def format_file_detail(item: dict) -> str:
    return (
        "File detail loaded successfully.\n\n"
        f"Name: {item.get('plaintext_filename', '-')}\n"
        f"Size: {item.get('plaintext_size_bytes', '-')}\n"
        f"ID: {item.get('file_id', '-')}\n"
        f"User ID: {item.get('user_id', '-')}\n"
        f"State: {item.get('state', '-')}\n"
        f"Current version: {item.get('current_version', '-')}\n"
        f"Created by device ID: {item.get('created_by_device_id', '-')}\n"
        f"Created at: {item.get('created_at', '-')}\n\n"
        "Encrypted manifest:\n"
        f"{json.dumps(item.get('encrypted_manifest'), indent=2)}\n\n"
        "Encryption header:\n"
        f"{json.dumps(item.get('encryption_header'), indent=2)}\n\n"
        "Blobs:\n"
        f"{json.dumps(item.get('blobs'), indent=2)}"
    )
