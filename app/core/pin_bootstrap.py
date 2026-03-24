from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from vault_crypto.encoding import b64decode_text, b64encode_bytes
from vault_crypto.envelopes import (
    EncryptedPayloadEnvelope,
    EncryptionHeader,
    decrypt_payload,
    encrypt_payload,
)

DEFAULT_PIN_KDF_ITERATIONS = 200_000
MIN_PIN_LENGTH = 4
PIN_BOOTSTRAP_SCHEMA_VERSION = 1
PIN_BOOTSTRAP_OBJECT_TYPE = "desktop_pin_bootstrap"


@dataclass(frozen=True)
class LocalPinBootstrap:
    schema_version: int
    user_id: str
    identifier_hint: str
    kdf_salt_b64: str
    kdf_iterations: int
    wrapped_master_key_ciphertext_b64: str
    wrapped_master_key_header: dict


class LocalPinBootstrapStore:
    def __init__(self, config_path: Path | None = None) -> None:
        self.config_path = config_path or (
            Path.home() / ".config" / "vault-desktop" / "pin_bootstrap.json"
        )

    def load(self) -> LocalPinBootstrap | None:
        if not self.config_path.exists():
            return None

        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        return LocalPinBootstrap(
            schema_version=int(data.get("schema_version", PIN_BOOTSTRAP_SCHEMA_VERSION)),
            user_id=str(data.get("user_id", "")),
            identifier_hint=str(data.get("identifier_hint", "")),
            kdf_salt_b64=str(data.get("kdf_salt_b64", "")),
            kdf_iterations=int(data.get("kdf_iterations", DEFAULT_PIN_KDF_ITERATIONS)),
            wrapped_master_key_ciphertext_b64=str(
                data.get("wrapped_master_key_ciphertext_b64", "")
            ),
            wrapped_master_key_header=dict(data.get("wrapped_master_key_header", {})),
        )

    def save(self, bootstrap: LocalPinBootstrap) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            json.dumps(asdict(bootstrap), indent=2),
            encoding="utf-8",
        )

    def clear(self) -> None:
        if self.config_path.exists():
            self.config_path.unlink()


def _validate_master_key_b64(master_key_b64: str) -> str:
    key = b64decode_text(master_key_b64)
    if len(key) != 32:
        raise ValueError("master_key_b64 must decode to exactly 32 bytes")
    return master_key_b64


def validate_pin(pin: str) -> str:
    value = pin.strip()
    if len(value) < MIN_PIN_LENGTH:
        raise ValueError(f"PIN must contain at least {MIN_PIN_LENGTH} characters.")
    if len(value) > 128:
        raise ValueError("PIN must contain at most 128 characters.")
    return value


def _derive_pin_wrap_key(*, pin: str, salt_b64: str, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        validate_pin(pin).encode("utf-8"),
        b64decode_text(salt_b64),
        iterations,
        dklen=32,
    )


def create_local_pin_bootstrap(
    *,
    user_id: str,
    identifier_hint: str,
    pin: str,
    master_key_b64: str,
    iterations: int = DEFAULT_PIN_KDF_ITERATIONS,
) -> LocalPinBootstrap:
    validated_master_key_b64 = _validate_master_key_b64(master_key_b64)
    validated_pin = validate_pin(pin)

    salt = os.urandom(16)
    salt_b64 = b64encode_bytes(salt)
    wrap_key = hashlib.pbkdf2_hmac(
        "sha256",
        validated_pin.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )

    envelope = encrypt_payload(
        key=wrap_key,
        object_type=PIN_BOOTSTRAP_OBJECT_TYPE,
        object_id=user_id or identifier_hint or "local-device",
        object_version=PIN_BOOTSTRAP_SCHEMA_VERSION,
        plaintext=validated_master_key_b64.encode("utf-8"),
    )

    return LocalPinBootstrap(
        schema_version=PIN_BOOTSTRAP_SCHEMA_VERSION,
        user_id=user_id,
        identifier_hint=identifier_hint,
        kdf_salt_b64=salt_b64,
        kdf_iterations=iterations,
        wrapped_master_key_ciphertext_b64=envelope.ciphertext_b64,
        wrapped_master_key_header=envelope.header.to_dict(),
    )


def unlock_master_key_b64_with_pin(
    *,
    bootstrap: LocalPinBootstrap,
    pin: str,
) -> str:
    wrap_key = _derive_pin_wrap_key(
        pin=pin,
        salt_b64=bootstrap.kdf_salt_b64,
        iterations=bootstrap.kdf_iterations,
    )

    try:
        plaintext = decrypt_payload(
            key=wrap_key,
            envelope=EncryptedPayloadEnvelope(
                header=EncryptionHeader.from_dict(bootstrap.wrapped_master_key_header),
                ciphertext_b64=bootstrap.wrapped_master_key_ciphertext_b64,
            ),
        )
    except Exception as exc:  # pragma: no cover - exact crypto exception type is implementation detail
        raise ValueError("PIN unlock failed.") from exc

    return _validate_master_key_b64(plaintext.decode("utf-8"))
