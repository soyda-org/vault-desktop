from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from vault_crypto.envelopes import (
    EncryptedPayloadEnvelope,
    EncryptionHeader,
    decrypt_payload,
    encrypt_payload,
)
from vault_crypto.keys import HkdfKeyContext, KeyPurpose, derive_hkdf_subkey
from vault_crypto.serialization import dumps_canonical_bytes, loads_json

from app.services.file_crypto_bridge import parse_dev_aes256_key_b64


@dataclass(frozen=True)
class EncryptedItemFinalizePayload:
    object_type: str
    object_id: str
    object_version: int
    encrypted_metadata: dict[str, Any] | None
    encrypted_payload: dict[str, Any]
    encryption_header: dict[str, Any]


@dataclass(frozen=True)
class DecryptedItemDetail:
    object_type: str
    object_id: str
    object_version: int
    plaintext_metadata: dict[str, Any] | None
    plaintext_payload: dict[str, Any]


def _derive_item_part_key(
    *,
    master_key: bytes,
    object_type: str,
    object_id: str,
    object_version: int,
    part: str,
) -> bytes:
    return derive_hkdf_subkey(
        master_key=master_key,
        context=HkdfKeyContext(
            purpose=KeyPurpose.ITEM_DEK,
            object_type=f"{object_type}_{part}",
            object_id=object_id,
            object_version=object_version,
        ),
    )


def build_encrypted_item_finalize_payload(
    *,
    object_type: str,
    object_id: str,
    object_version: int,
    plaintext_payload: dict[str, Any],
    master_key_b64: str,
    plaintext_metadata: dict[str, Any] | None = None,
) -> EncryptedItemFinalizePayload:
    if not object_type.strip():
        raise ValueError("object_type must not be empty")
    if not object_id.strip():
        raise ValueError("object_id must not be empty")
    if object_version < 1:
        raise ValueError("object_version must be >= 1")
    if not isinstance(plaintext_payload, dict):
        raise TypeError("plaintext_payload must be a dict")
    if plaintext_metadata is not None and not isinstance(plaintext_metadata, dict):
        raise TypeError("plaintext_metadata must be a dict or None")

    master_key = parse_dev_aes256_key_b64(master_key_b64)

    payload_key = _derive_item_part_key(
        master_key=master_key,
        object_type=object_type,
        object_id=object_id,
        object_version=object_version,
        part="payload",
    )
    payload_envelope = encrypt_payload(
        key=payload_key,
        object_type=f"{object_type}_payload",
        object_id=object_id,
        object_version=object_version,
        plaintext=dumps_canonical_bytes(plaintext_payload),
    )

    encrypted_metadata: dict[str, Any] | None = None
    if plaintext_metadata is not None:
        metadata_key = _derive_item_part_key(
            master_key=master_key,
            object_type=object_type,
            object_id=object_id,
            object_version=object_version,
            part="metadata",
        )
        metadata_envelope = encrypt_payload(
            key=metadata_key,
            object_type=f"{object_type}_metadata",
            object_id=object_id,
            object_version=object_version,
            plaintext=dumps_canonical_bytes(plaintext_metadata),
        )
        encrypted_metadata = metadata_envelope.to_dict()

    return EncryptedItemFinalizePayload(
        object_type=object_type,
        object_id=object_id,
        object_version=object_version,
        encrypted_metadata=encrypted_metadata,
        encrypted_payload=payload_envelope.to_dict(),
        encryption_header=payload_envelope.header.to_dict(),
    )


def _payload_envelope_from_detail(
    *,
    encrypted_value: dict[str, Any] | None,
    fallback_header: dict[str, Any] | None,
) -> EncryptedPayloadEnvelope | None:
    if encrypted_value is None:
        return None

    if "header" in encrypted_value:
        return EncryptedPayloadEnvelope.from_dict(encrypted_value)

    ciphertext_b64 = encrypted_value.get("ciphertext_b64")
    if not isinstance(ciphertext_b64, str) or not ciphertext_b64.strip():
        raise ValueError("Encrypted payload is missing ciphertext_b64")

    if fallback_header is None:
        raise ValueError("Missing encryption header for legacy payload structure")

    return EncryptedPayloadEnvelope(
        header=EncryptionHeader.from_dict(fallback_header),
        ciphertext_b64=ciphertext_b64,
    )


def decrypt_item_detail(
    *,
    item: dict[str, Any],
    master_key_b64: str,
) -> DecryptedItemDetail:
    if "credential_id" in item:
        object_type = "credential"
        object_id = str(item["credential_id"])
    elif "note_id" in item:
        object_type = "note"
        object_id = str(item["note_id"])
    else:
        raise ValueError("Unsupported item detail payload")

    object_version = int(item["current_version"])
    fallback_header = item.get("encryption_header")
    master_key = parse_dev_aes256_key_b64(master_key_b64)

    payload_envelope = _payload_envelope_from_detail(
        encrypted_value=item.get("encrypted_payload"),
        fallback_header=fallback_header,
    )
    if payload_envelope is None:
        raise ValueError("Missing encrypted payload")

    payload_key = _derive_item_part_key(
        master_key=master_key,
        object_type=object_type,
        object_id=object_id,
        object_version=object_version,
        part="payload",
    )
    plaintext_payload = loads_json(
        decrypt_payload(key=payload_key, envelope=payload_envelope)
    )
    if not isinstance(plaintext_payload, dict):
        raise ValueError("Decrypted payload must be a JSON object")

    plaintext_metadata: dict[str, Any] | None = None
    encrypted_metadata = item.get("encrypted_metadata")
    if isinstance(encrypted_metadata, dict) and encrypted_metadata:
        metadata_envelope = _payload_envelope_from_detail(
            encrypted_value=encrypted_metadata,
            fallback_header=None,
        )
        if metadata_envelope is not None:
            metadata_key = _derive_item_part_key(
                master_key=master_key,
                object_type=object_type,
                object_id=object_id,
                object_version=object_version,
                part="metadata",
            )
            decrypted_metadata = loads_json(
                decrypt_payload(key=metadata_key, envelope=metadata_envelope)
            )
            if not isinstance(decrypted_metadata, dict):
                raise ValueError("Decrypted metadata must be a JSON object")
            plaintext_metadata = decrypted_metadata

    return DecryptedItemDetail(
        object_type=object_type,
        object_id=object_id,
        object_version=object_version,
        plaintext_metadata=plaintext_metadata,
        plaintext_payload=plaintext_payload,
    )
