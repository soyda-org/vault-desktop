from __future__ import annotations


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
