"""Small dependency-free password/session primitives for the Web Console.

Password hashes use scrypt from the Python standard library. Session and CSRF
values are generated from ``secrets`` and only their SHA-256 digests are stored.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("password must be non-empty")
    salt = secrets.token_bytes(16)
    # Parameters are deliberately encoded so a future deployment can migrate
    # without treating a stored hash as an opaque algorithm-specific value.
    n, r, p = 2**14, 8, 1
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_text, digest_text = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        expected = _unb64(digest_text)
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=_unb64(salt_text),
            n=int(n), r=int(r), p=int(p), dklen=len(expected),
        )
    except (AttributeError, TypeError, ValueError, base64.binascii.Error):
        return False
    return hmac.compare_digest(actual, expected)


def digest_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)
