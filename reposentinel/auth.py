from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets


PASSWORD_ITERATIONS = 600_000
SESSION_TTL = timedelta(hours=12)


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if "@" not in normalized or len(normalized) > 320:
        raise ValueError("A valid email address is required")
    return normalized


def hash_password(password: str) -> str:
    if len(password) < 12 or len(password) > 256:
        raise ValueError("Password must be between 12 and 256 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_text, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return hmac.compare_digest(actual, expected)


def new_session_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


def session_expiry() -> str:
    return (datetime.now(timezone.utc) + SESSION_TTL).isoformat()
