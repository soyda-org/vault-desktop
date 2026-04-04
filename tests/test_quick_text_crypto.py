import pytest

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


@pytest.mark.parametrize("label,method_key", available_method_labels())
def test_quick_text_crypto_roundtrip_for_each_method(label: str, method_key: str) -> None:
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

    assert decrypted == plaintext
    assert detected_method == method_key


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
