from __future__ import annotations

from dataclasses import dataclass
import json
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16


@dataclass(frozen=True)
class QuickTextCryptoMethod:
    key: str
    label: str
    key_length: int
    nonce_length: int


METHODS: tuple[QuickTextCryptoMethod, ...] = (
    QuickTextCryptoMethod("aes-256-gcm", "AES-256-GCM", 32, 12),
    QuickTextCryptoMethod("aes-128-gcm", "AES-128-GCM", 16, 12),
    QuickTextCryptoMethod("chacha20-poly1305", "ChaCha20-Poly1305", 32, 12),
    QuickTextCryptoMethod("aes-256-ccm", "AES-256-CCM", 32, 13),
)

METHODS_BY_KEY = {method.key: method for method in METHODS}


class QuickTextCryptoError(ValueError):
    pass


def available_method_labels() -> tuple[tuple[str, str], ...]:
    return tuple((method.label, method.key) for method in METHODS)


def _method_for_key(method_key: str) -> QuickTextCryptoMethod:
    method = METHODS_BY_KEY.get(method_key)
    if method is None:
        raise QuickTextCryptoError(f"Unsupported method: {method_key}")
    return method


def _derive_key(*, passphrase: str, salt: bytes, key_length: int) -> bytes:
    if not passphrase:
        raise QuickTextCryptoError("Passphrase is required.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _aead_encrypt(*, method: QuickTextCryptoMethod, key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    if method.key in {"aes-256-gcm", "aes-128-gcm"}:
        return AESGCM(key).encrypt(nonce, plaintext, None)
    if method.key == "chacha20-poly1305":
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    if method.key == "aes-256-ccm":
        return AESCCM(key).encrypt(nonce, plaintext, None)
    raise QuickTextCryptoError(f"Unsupported method: {method.key}")


def _aead_decrypt(*, method: QuickTextCryptoMethod, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    try:
        if method.key in {"aes-256-gcm", "aes-128-gcm"}:
            return AESGCM(key).decrypt(nonce, ciphertext, None)
        if method.key == "chacha20-poly1305":
            return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
        if method.key == "aes-256-ccm":
            return AESCCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise QuickTextCryptoError("Decrypt failed. Check the passphrase or payload.") from exc
    raise QuickTextCryptoError(f"Unsupported method: {method.key}")


def encrypt_text(*, plaintext: str, passphrase: str, method_key: str) -> str:
    if not plaintext:
        raise QuickTextCryptoError("Input text is required.")

    method = _method_for_key(method_key)
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(method.nonce_length)
    key = _derive_key(passphrase=passphrase, salt=salt, key_length=method.key_length)
    ciphertext = _aead_encrypt(
        method=method,
        key=key,
        nonce=nonce,
        plaintext=plaintext.encode("utf-8"),
    )
    envelope = {
        "format": "quick-text-v1",
        "method": method.key,
        "kdf": "pbkdf2-sha256",
        "iterations": PBKDF2_ITERATIONS,
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
    }
    return json.dumps(envelope, indent=2)


def decrypt_text(*, envelope_text: str, passphrase: str) -> tuple[str, str]:
    if not envelope_text.strip():
        raise QuickTextCryptoError("Encrypted payload is required.")

    if not passphrase:
        raise QuickTextCryptoError("Passphrase is required.")

    try:
        envelope = json.loads(envelope_text)
    except json.JSONDecodeError as exc:
        raise QuickTextCryptoError("Encrypted payload must be valid JSON.") from exc

    if not isinstance(envelope, dict):
        raise QuickTextCryptoError("Encrypted payload must be a JSON object.")

    if envelope.get("format") != "quick-text-v1":
        raise QuickTextCryptoError("Unsupported encrypted payload format.")
    if envelope.get("kdf") != "pbkdf2-sha256":
        raise QuickTextCryptoError("Unsupported KDF in encrypted payload.")

    method = _method_for_key(str(envelope.get("method", "")))
    try:
        iterations = int(envelope["iterations"])
        salt = bytes.fromhex(str(envelope["salt_hex"]))
        nonce = bytes.fromhex(str(envelope["nonce_hex"]))
        ciphertext = bytes.fromhex(str(envelope["ciphertext_hex"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise QuickTextCryptoError("Encrypted payload is missing required fields.") from exc

    if iterations != PBKDF2_ITERATIONS:
        raise QuickTextCryptoError("Unsupported PBKDF2 iteration count in encrypted payload.")

    key = _derive_key(passphrase=passphrase, salt=salt, key_length=method.key_length)
    plaintext = _aead_decrypt(method=method, key=key, nonce=nonce, ciphertext=ciphertext)
    return plaintext.decode("utf-8"), method.key
