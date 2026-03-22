from __future__ import annotations

import json


def credential_list_label(item: dict) -> str:
    return (
        f"{item.get('credential_id', '-')}"
        f" | {item.get('state', '-')}"
        f" | v{item.get('current_version', '-')}"
    )


def note_list_label(item: dict) -> str:
    return (
        f"{item.get('note_id', '-')}"
        f" | {item.get('note_type', '-')}"
        f" | {item.get('state', '-')}"
        f" | v{item.get('current_version', '-')}"
    )


def file_list_label(item: dict) -> str:
    return (
        f"{item.get('file_id', '-')}"
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
                f"  ID: {item.get('file_id', '-')}",
                f"  State: {item.get('state', '-')}",
                f"  Current version: {item.get('current_version', '-')}",
                f"  Updated at: {item.get('updated_at', '-')}",
                "",
            ]
        )

    return "\n".join(lines).rstrip()


def format_credential_detail(item: dict) -> str:
    return (
        "Credential detail loaded successfully.\n\n"
        f"ID: {item.get('credential_id', '-')}\n"
        f"User ID: {item.get('user_id', '-')}\n"
        f"State: {item.get('state', '-')}\n"
        f"Current version: {item.get('current_version', '-')}\n"
        f"Created by device ID: {item.get('created_by_device_id', '-')}\n"
        f"Created at: {item.get('created_at', '-')}\n\n"
        "Encrypted metadata:\n"
        f"{json.dumps(item.get('encrypted_metadata'), indent=2)}\n\n"
        "Encrypted payload:\n"
        f"{json.dumps(item.get('encrypted_payload'), indent=2)}\n\n"
        "Encryption header:\n"
        f"{json.dumps(item.get('encryption_header'), indent=2)}"
    )


def format_note_detail(item: dict) -> str:
    return (
        "Note detail loaded successfully.\n\n"
        f"ID: {item.get('note_id', '-')}\n"
        f"User ID: {item.get('user_id', '-')}\n"
        f"Type: {item.get('note_type', '-')}\n"
        f"State: {item.get('state', '-')}\n"
        f"Current version: {item.get('current_version', '-')}\n"
        f"Created by device ID: {item.get('created_by_device_id', '-')}\n"
        f"Created at: {item.get('created_at', '-')}\n\n"
        "Encrypted metadata:\n"
        f"{json.dumps(item.get('encrypted_metadata'), indent=2)}\n\n"
        "Encrypted payload:\n"
        f"{json.dumps(item.get('encrypted_payload'), indent=2)}\n\n"
        "Encryption header:\n"
        f"{json.dumps(item.get('encryption_header'), indent=2)}"
    )


def format_file_detail(item: dict) -> str:
    return (
        "File detail loaded successfully.\n\n"
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
