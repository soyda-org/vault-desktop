from __future__ import annotations

import secrets
import string
from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordPolicy:
    length: int = 24
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True


class PasswordGenerationError(ValueError):
    pass


SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

def _choice_from_charset(charset: str) -> str:
    return secrets.choice(charset)


def generate_password(policy: PasswordPolicy) -> str:
    if policy.length < 8:
        raise PasswordGenerationError("Password length must be at least 8")

    required_sets: list[str] = []

    if policy.use_uppercase:
        required_sets.append(string.ascii_uppercase)
    if policy.use_lowercase:
        required_sets.append(string.ascii_lowercase)
    if policy.use_digits:
        required_sets.append(string.digits)
    if policy.use_symbols:
        required_sets.append(SYMBOLS)

    if not required_sets:
        raise PasswordGenerationError("At least one character set must be enabled")

    if policy.length < len(required_sets):
        raise PasswordGenerationError(
            "Password length is too short for the selected character sets"
        )

    all_chars = "".join(required_sets)

    password_chars = [_choice_from_charset(charset) for charset in required_sets]

    remaining = policy.length - len(password_chars)
    password_chars.extend(_choice_from_charset(all_chars) for _ in range(remaining))

    # Secure shuffle
    for index in range(len(password_chars) - 1, 0, -1):
        swap_index = secrets.randbelow(index + 1)
        password_chars[index], password_chars[swap_index] = (
            password_chars[swap_index],
            password_chars[index],
        )

    return "".join(password_chars)
