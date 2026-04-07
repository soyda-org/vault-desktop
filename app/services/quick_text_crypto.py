from __future__ import annotations

import base64
import codecs
from dataclasses import dataclass
import json
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
DEFAULT_CAESAR_SHIFT = 13
MORSE_CHAR_TO_CODE = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    ".": ".-.-.-",
    ",": "--..--",
    "?": "..--..",
    "!": "-.-.--",
    ":": "---...",
    ";": "-.-.-.",
    "-": "-....-",
    "/": "-..-.",
    "@": ".--.-.",
    "(": "-.--.",
    ")": "-.--.-",
    "&": ".-...",
    "'": ".----.",
    "\"": ".-..-.",
    "=": "-...-",
    "+": ".-.-.",
    "_": "..--.-",
}
MORSE_CODE_TO_CHAR = {value: key for key, value in MORSE_CHAR_TO_CODE.items()}


@dataclass(frozen=True)
class QuickTextCryptoMethod:
    key: str
    label: str
    passphrase_mode: str
    family: str
    summary: str
    key_length: int = 0
    nonce_length: int = 0


METHODS: tuple[QuickTextCryptoMethod, ...] = (
    QuickTextCryptoMethod("base64", "Base64", "none", "base64", "Encodes plain text as Base64 text. It is reversible and gives no secrecy."),
    QuickTextCryptoMethod("hex", "Hex", "none", "hex", "Converts bytes to hexadecimal text. Easy to inspect, but not secure."),
    QuickTextCryptoMethod("sha-1", "SHA-1", "none", "hash", "Computes a SHA-1 digest of the text. This is a one-way hash and cannot be decrypted."),
    QuickTextCryptoMethod("sha-224", "SHA-224", "none", "hash", "Computes a SHA-224 digest of the text. This is a one-way hash and cannot be decrypted."),
    QuickTextCryptoMethod("sha-256", "SHA-256", "none", "hash", "Computes a SHA-256 digest of the text. This is a one-way hash and cannot be decrypted."),
    QuickTextCryptoMethod("sha-384", "SHA-384", "none", "hash", "Computes a SHA-384 digest of the text. This is a one-way hash and cannot be decrypted."),
    QuickTextCryptoMethod("sha-512", "SHA-512", "none", "hash", "Computes a SHA-512 digest of the text. This is a one-way hash and cannot be decrypted."),
    QuickTextCryptoMethod("sha3-256", "SHA3-256", "none", "hash", "Computes a SHA3-256 digest of the text. This is a one-way hash and cannot be decrypted."),
    QuickTextCryptoMethod("sha3-512", "SHA3-512", "none", "hash", "Computes a SHA3-512 digest of the text. This is a one-way hash and cannot be decrypted."),
    QuickTextCryptoMethod("rot13", "ROT13", "none", "rot13", "Rotates letters by 13 positions. It only obscures text and is trivially reversible."),
    QuickTextCryptoMethod("morse", "Morse", "none", "morse", "Maps supported letters, digits, and punctuation into Morse code and back. This is a representation change, not encryption."),
    QuickTextCryptoMethod("caesar-shift", "Caesar Shift", "optional", "caesar", "Shifts letters through the alphabet. With no passphrase it uses a default shift; with one, the shift changes. This is obfuscation, not strong encryption."),
    QuickTextCryptoMethod("xor-stream", "XOR Stream", "required", "xor", "XORs each byte against a repeating passphrase-derived stream. It hides text, but is much weaker than modern authenticated encryption."),
    QuickTextCryptoMethod("aes-128-gcm", "AES-128-GCM", "required", "aead", "Derives a key from the passphrase and encrypts with AES-GCM. This is real authenticated encryption and detects tampering.", 16, 12),
    QuickTextCryptoMethod("aes-256-gcm", "AES-256-GCM", "required", "aead", "Derives a longer key from the passphrase and encrypts with AES-256-GCM. This is real authenticated encryption and detects tampering.", 32, 12),
    QuickTextCryptoMethod("chacha20-poly1305", "ChaCha20-Poly1305", "required", "aead", "Derives a key from the passphrase and encrypts with ChaCha20-Poly1305. This is real authenticated encryption and detects tampering.", 32, 12),
    QuickTextCryptoMethod("aes-256-ccm", "AES-256-CCM", "required", "aead", "Derives a key from the passphrase and encrypts with AES-256-CCM. This is real authenticated encryption and detects tampering.", 32, 13),
)

METHODS_BY_KEY = {method.key: method for method in METHODS}


class QuickTextCryptoError(ValueError):
    pass


def available_method_labels() -> tuple[tuple[str, str], ...]:
    return tuple((method.label, method.key) for method in METHODS)


def passphrase_mode_for_method(method_key: str) -> str:
    return _method_for_key(method_key).passphrase_mode


def method_summary_for_key(method_key: str) -> str:
    return _method_for_key(method_key).summary


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


def _caesar_shift_from_passphrase(passphrase: str) -> int:
    if not passphrase:
        return DEFAULT_CAESAR_SHIFT
    return sum(passphrase.encode("utf-8")) % 26 or DEFAULT_CAESAR_SHIFT


def _apply_caesar(text: str, shift: int) -> str:
    output: list[str] = []
    for char in text:
        if "a" <= char <= "z":
            output.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            output.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
        else:
            output.append(char)
    return "".join(output)


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise QuickTextCryptoError("Passphrase is required.")
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def _encode_morse(text: str) -> str:
    words: list[str] = []
    for word in text.upper().split():
        encoded_letters: list[str] = []
        for char in word:
            code = MORSE_CHAR_TO_CODE.get(char)
            if code is None:
                raise QuickTextCryptoError(f"Morse does not support character: {char}")
            encoded_letters.append(code)
        words.append(" ".join(encoded_letters))
    return " / ".join(words)


def _decode_morse(text: str) -> str:
    words: list[str] = []
    for word in text.split(" / "):
        decoded_letters: list[str] = []
        for code in word.split():
            char = MORSE_CODE_TO_CHAR.get(code)
            if char is None:
                raise QuickTextCryptoError(f"Unsupported Morse code: {code}")
            decoded_letters.append(char)
        words.append("".join(decoded_letters))
    return " ".join(words)


def _decode_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QuickTextCryptoError("Decrypted payload is not valid UTF-8 text.") from exc


def _hash_digest_hex(*, method_key: str, plaintext: str) -> str:
    digest = hashes.Hash(
        {
            "sha-1": hashes.SHA1(),
            "sha-224": hashes.SHA224(),
            "sha-256": hashes.SHA256(),
            "sha-384": hashes.SHA384(),
            "sha-512": hashes.SHA512(),
            "sha3-256": hashes.SHA3_256(),
            "sha3-512": hashes.SHA3_512(),
        }[method_key]
    )
    digest.update(plaintext.encode("utf-8"))
    return digest.finalize().hex()


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

    if method.family == "base64":
        return json.dumps(
            {
                "format": "quick-text-v1",
                "method": method.key,
                "payload_text": base64.b64encode(plaintext.encode("utf-8")).decode("ascii"),
            },
            indent=2,
        )
    if method.family == "hex":
        return json.dumps(
            {
                "format": "quick-text-v1",
                "method": method.key,
                "payload_text": plaintext.encode("utf-8").hex(),
            },
            indent=2,
        )
    if method.family == "hash":
        return json.dumps(
            {
                "format": "quick-text-v1",
                "method": method.key,
                "digest_hex": _hash_digest_hex(method_key=method.key, plaintext=plaintext),
            },
            indent=2,
        )
    if method.family == "rot13":
        return json.dumps(
            {
                "format": "quick-text-v1",
                "method": method.key,
                "payload_text": codecs.encode(plaintext, "rot_13"),
            },
            indent=2,
        )
    if method.family == "morse":
        return json.dumps(
            {
                "format": "quick-text-v1",
                "method": method.key,
                "payload_text": _encode_morse(plaintext),
            },
            indent=2,
        )
    if method.family == "caesar":
        shift = _caesar_shift_from_passphrase(passphrase)
        return json.dumps(
            {
                "format": "quick-text-v1",
                "method": method.key,
                "shift": shift,
                "payload_text": _apply_caesar(plaintext, shift),
            },
            indent=2,
        )
    if method.family == "xor":
        ciphertext = _xor_bytes(plaintext.encode("utf-8"), passphrase.encode("utf-8"))
        return json.dumps(
            {
                "format": "quick-text-v1",
                "method": method.key,
                "ciphertext_hex": ciphertext.hex(),
            },
            indent=2,
        )
    if method.family == "aead":
        salt = secrets.token_bytes(SALT_BYTES)
        nonce = secrets.token_bytes(method.nonce_length)
        key = _derive_key(passphrase=passphrase, salt=salt, key_length=method.key_length)
        ciphertext = _aead_encrypt(
            method=method,
            key=key,
            nonce=nonce,
            plaintext=plaintext.encode("utf-8"),
        )
        return json.dumps(
            {
                "format": "quick-text-v1",
                "method": method.key,
                "kdf": "pbkdf2-sha256",
                "iterations": PBKDF2_ITERATIONS,
                "salt_hex": salt.hex(),
                "nonce_hex": nonce.hex(),
                "ciphertext_hex": ciphertext.hex(),
            },
            indent=2,
        )

    raise QuickTextCryptoError(f"Unsupported method: {method.key}")


def decrypt_text(*, envelope_text: str, passphrase: str) -> tuple[str, str]:
    if not envelope_text.strip():
        raise QuickTextCryptoError("Encrypted payload is required.")

    try:
        envelope = json.loads(envelope_text)
    except json.JSONDecodeError as exc:
        raise QuickTextCryptoError("Encrypted payload must be valid JSON.") from exc

    if not isinstance(envelope, dict):
        raise QuickTextCryptoError("Encrypted payload must be a JSON object.")
    if envelope.get("format") != "quick-text-v1":
        raise QuickTextCryptoError("Unsupported encrypted payload format.")

    method = _method_for_key(str(envelope.get("method", "")))

    if method.family == "hash":
        raise QuickTextCryptoError("Hash methods are one-way and cannot be decrypted.")

    if method.family == "base64":
        try:
            payload = base64.b64decode(str(envelope["payload_text"]))
        except (KeyError, ValueError) as exc:
            raise QuickTextCryptoError("Encrypted payload is missing required fields.") from exc
        return _decode_utf8(payload), method.key

    if method.family == "hex":
        try:
            payload = bytes.fromhex(str(envelope["payload_text"]))
        except (KeyError, ValueError) as exc:
            raise QuickTextCryptoError("Encrypted payload is missing required fields.") from exc
        return _decode_utf8(payload), method.key

    if method.family == "rot13":
        try:
            payload_text = str(envelope["payload_text"])
        except KeyError as exc:
            raise QuickTextCryptoError("Encrypted payload is missing required fields.") from exc
        return codecs.decode(payload_text, "rot_13"), method.key

    if method.family == "morse":
        try:
            payload_text = str(envelope["payload_text"])
        except KeyError as exc:
            raise QuickTextCryptoError("Encrypted payload is missing required fields.") from exc
        return _decode_morse(payload_text), method.key

    if method.family == "caesar":
        try:
            shift = int(envelope["shift"])
            payload_text = str(envelope["payload_text"])
        except (KeyError, TypeError, ValueError) as exc:
            raise QuickTextCryptoError("Encrypted payload is missing required fields.") from exc
        return _apply_caesar(payload_text, -shift), method.key

    if method.family == "xor":
        try:
            ciphertext = bytes.fromhex(str(envelope["ciphertext_hex"]))
        except (KeyError, ValueError) as exc:
            raise QuickTextCryptoError("Encrypted payload is missing required fields.") from exc
        return _decode_utf8(_xor_bytes(ciphertext, passphrase.encode("utf-8"))), method.key

    if method.family == "aead":
        if envelope.get("kdf") != "pbkdf2-sha256":
            raise QuickTextCryptoError("Unsupported KDF in encrypted payload.")
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
        return _decode_utf8(plaintext), method.key

    raise QuickTextCryptoError(f"Unsupported method: {method.key}")
