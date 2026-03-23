import base64

from app.services.item_crypto_bridge import (
    build_encrypted_item_finalize_payload,
    decrypt_item_detail,
)


VALID_MASTER_KEY_B64 = base64.b64encode(b"K" * 32).decode("ascii")


def test_item_crypto_bridge_roundtrip_for_credential() -> None:
    payload = build_encrypted_item_finalize_payload(
        object_type="credential",
        object_id="cred_001",
        object_version=1,
        plaintext_metadata={"label": "Personal"},
        plaintext_payload={
            "username": "alice",
            "secret": "s3cr3t",
            "url": "https://example.com",
        },
        master_key_b64=VALID_MASTER_KEY_B64,
    )

    result = decrypt_item_detail(
        item={
            "credential_id": "cred_001",
            "current_version": 1,
            "encrypted_metadata": payload.encrypted_metadata,
            "encrypted_payload": payload.encrypted_payload,
            "encryption_header": payload.encryption_header,
        },
        master_key_b64=VALID_MASTER_KEY_B64,
    )

    assert result.object_type == "credential"
    assert result.object_id == "cred_001"
    assert result.object_version == 1
    assert result.plaintext_metadata == {"label": "Personal"}
    assert result.plaintext_payload["username"] == "alice"
    assert result.plaintext_payload["secret"] == "s3cr3t"


def test_item_crypto_bridge_roundtrip_for_note() -> None:
    payload = build_encrypted_item_finalize_payload(
        object_type="note",
        object_id="note_001",
        object_version=1,
        plaintext_metadata=None,
        plaintext_payload={
            "title": "todo",
            "content": "buy milk",
        },
        master_key_b64=VALID_MASTER_KEY_B64,
    )

    result = decrypt_item_detail(
        item={
            "note_id": "note_001",
            "current_version": 1,
            "encrypted_metadata": None,
            "encrypted_payload": payload.encrypted_payload,
            "encryption_header": payload.encryption_header,
            "note_type": "note",
        },
        master_key_b64=VALID_MASTER_KEY_B64,
    )

    assert result.object_type == "note"
    assert result.object_id == "note_001"
    assert result.plaintext_metadata is None
    assert result.plaintext_payload == {
        "title": "todo",
        "content": "buy milk",
    }


def test_item_crypto_bridge_supports_legacy_payload_header_shape() -> None:
    payload = build_encrypted_item_finalize_payload(
        object_type="credential",
        object_id="cred_legacy_001",
        object_version=1,
        plaintext_metadata=None,
        plaintext_payload={"username": "alice"},
        master_key_b64=VALID_MASTER_KEY_B64,
    )

    encrypted_payload = {
        "ciphertext_b64": payload.encrypted_payload["ciphertext_b64"],
    }

    result = decrypt_item_detail(
        item={
            "credential_id": "cred_legacy_001",
            "current_version": 1,
            "encrypted_metadata": None,
            "encrypted_payload": encrypted_payload,
            "encryption_header": payload.encryption_header,
        },
        master_key_b64=VALID_MASTER_KEY_B64,
    )

    assert result.plaintext_payload == {"username": "alice"}
