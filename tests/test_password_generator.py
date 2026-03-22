import string

import pytest

from app.services.password_generator import (
    PasswordGenerationError,
    PasswordPolicy,
    generate_password,
)


def test_generate_password_uses_requested_length() -> None:
    password = generate_password(PasswordPolicy(length=32))

    assert len(password) == 32


def test_generate_password_includes_required_character_sets() -> None:
    password = generate_password(
        PasswordPolicy(
            length=32,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_symbols=True,
        )
    )

    assert any(char in string.ascii_uppercase for char in password)
    assert any(char in string.ascii_lowercase for char in password)
    assert any(char in string.digits for char in password)
    assert any(char in "!@#$%^&*()-_=+[]{};:,.?/" for char in password)


def test_generate_password_with_only_digits() -> None:
    password = generate_password(
        PasswordPolicy(
            length=16,
            use_uppercase=False,
            use_lowercase=False,
            use_digits=True,
            use_symbols=False,
        )
    )

    assert len(password) == 16
    assert all(char in string.digits for char in password)


def test_generate_password_rejects_too_short_length() -> None:
    with pytest.raises(PasswordGenerationError):
        generate_password(PasswordPolicy(length=7))


def test_generate_password_requires_at_least_one_charset() -> None:
    with pytest.raises(PasswordGenerationError):
        generate_password(
            PasswordPolicy(
                length=16,
                use_uppercase=False,
                use_lowercase=False,
                use_digits=False,
                use_symbols=False,
            )
        )


def test_generate_password_rejects_length_shorter_than_required_sets() -> None:
    with pytest.raises(PasswordGenerationError):
        generate_password(
            PasswordPolicy(
                length=3,
                use_uppercase=True,
                use_lowercase=True,
                use_digits=True,
                use_symbols=True,
            )
        )
