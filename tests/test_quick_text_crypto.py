import pytest
import json

from app.services.quick_text_crypto import (
    QuickTextCryptoError,
    available_method_labels,
    decrypt_text,
    encrypt_text,
    passphrase_mode_for_method,
)


def _passphrase_for_method(method_key: str) -> str:
    mode = passphrase_mode_for_method(method_key)
    if mode == "required":
        return "correct horse battery staple"
    if mode == "optional":
        return "seed"
    return ""


HASH_METHODS = {
    "sha-1",
    "sha-224",
    "sha-256",
    "sha-384",
    "sha-512",
    "sha3-256",
    "sha3-512",
}


@pytest.mark.parametrize("label,method_key", available_method_labels())
def test_quick_text_crypto_roundtrip_for_each_method(label: str, method_key: str) -> None:
    if method_key in HASH_METHODS:
        pytest.skip("Hash methods are one-way.")
    plaintext = f"hello from {label}"
    passphrase = _passphrase_for_method(method_key)

    encrypted = encrypt_text(
        plaintext=plaintext,
        passphrase=passphrase,
        method_key=method_key,
    )
    decrypted, detected_method = decrypt_text(
        envelope_text=encrypted,
        passphrase=passphrase,
    )

    expected_plaintext = plaintext.upper() if method_key == "morse" else plaintext
    assert decrypted == expected_plaintext
    assert detected_method == method_key


@pytest.mark.parametrize("method_key", sorted(HASH_METHODS))
def test_quick_text_crypto_hash_methods_emit_digest_and_reject_decrypt(method_key: str) -> None:
    encrypted = encrypt_text(
        plaintext="hello hash",
        passphrase="",
        method_key=method_key,
    )
    envelope = json.loads(encrypted)

    assert envelope["format"] == "quick-text-v1"
    assert envelope["method"] == method_key
    assert envelope["digest_hex"]

    with pytest.raises(QuickTextCryptoError, match="one-way"):
        decrypt_text(envelope_text=encrypted, passphrase="")


def test_quick_text_crypto_optional_passphrase_defaults_cleanly() -> None:
    encrypted = encrypt_text(
        plaintext="hello",
        passphrase="",
        method_key="caesar-shift",
    )

    decrypted, detected_method = decrypt_text(
        envelope_text=encrypted,
        passphrase="",
    )

    assert decrypted == "hello"
    assert detected_method == "caesar-shift"


def test_quick_text_crypto_morse_roundtrip_preserves_words() -> None:
    encrypted = encrypt_text(
        plaintext="SOS HELP",
        passphrase="",
        method_key="morse",
    )

    decrypted, detected_method = decrypt_text(
        envelope_text=encrypted,
        passphrase="",
    )

    assert decrypted == "SOS HELP"
    assert detected_method == "morse"


def test_quick_text_crypto_rejects_wrong_passphrase() -> None:
    encrypted = encrypt_text(
        plaintext="secret text",
        passphrase="good",
        method_key="aes-256-gcm",
    )

    with pytest.raises(QuickTextCryptoError, match="Decrypt failed"):
        decrypt_text(envelope_text=encrypted, passphrase="bad")


def test_quick_text_crypto_requires_passphrase_for_required_method() -> None:
    with pytest.raises(QuickTextCryptoError, match="Passphrase is required"):
        encrypt_text(
            plaintext="secret text",
            passphrase="",
            method_key="xor-stream",
        )


def test_quick_text_crypto_requires_json_for_decrypt() -> None:
    with pytest.raises(QuickTextCryptoError, match="valid JSON"):
        decrypt_text(envelope_text="not json", passphrase="pass")
