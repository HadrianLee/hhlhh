from __future__ import annotations

import asyncio
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
import hashlib
import hmac
import os
import secrets
from uuid import UUID


def _encode(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=32768, r=8, p=3,
        dklen=64, maxmem=64 * 1024 * 1024,
    )
    return f"scrypt$32768$8$3${_encode(salt)}${_encode(digest)}"


@dataclass(frozen=True)
class IdentitySettings:
    token_hmac_key: bytes
    refresh_ttl_seconds: int = 2592000
    verification_ttl_seconds: int = 3600
    password_reset_ttl_seconds: int = 1800

    @classmethod
    def from_env(cls) -> IdentitySettings:
        key = os.environ.get("IDENTITY_TOKEN_HMAC_KEY", "").encode("utf-8")
        if len(key) < 32:
            raise ValueError("IDENTITY_TOKEN_HMAC_KEY must contain at least 32 bytes")
        values = {
            "refresh_ttl_seconds": int(os.environ.get("IDENTITY_REFRESH_TOKEN_TTL_SECONDS", "2592000")),
            "verification_ttl_seconds": int(os.environ.get("IDENTITY_VERIFICATION_TOKEN_TTL_SECONDS", "3600")),
            "password_reset_ttl_seconds": int(os.environ.get("IDENTITY_PASSWORD_RESET_TOKEN_TTL_SECONDS", "1800")),
        }
        if any(value <= 0 for value in values.values()):
            raise ValueError("identity token lifetimes must be positive")
        return cls(token_hmac_key=key, **values)


class IdentitySecurity:
    def __init__(self, settings: IdentitySettings) -> None:
        self.settings = settings
        self._password_slots = asyncio.Semaphore(4)

    async def hash_password(self, password: str) -> str:
        async with self._password_slots:
            return await asyncio.to_thread(_hash_password, password, secrets.token_bytes(16))

    async def verify_password(self, password: str, password_hash: str | None) -> bool:
        salt = b"\x00" * 16
        expected = None
        try:
            algorithm, n, r, p, salt_text, digest_text = (password_hash or "").split("$")
            if (algorithm, n, r, p) == ("scrypt", "32768", "8", "3"):
                parsed_salt, parsed_digest = _decode(salt_text), _decode(digest_text)
                if len(parsed_salt) == 16 and len(parsed_digest) == 64:
                    salt, expected = parsed_salt, password_hash
        except (ValueError, TypeError):
            pass
        async with self._password_slots:
            actual = await asyncio.to_thread(_hash_password, password, salt)
        return hmac.compare_digest(actual, expected or "")

    def refresh_token(self, session_id: UUID) -> str:
        body = f"{session_id}.{secrets.token_urlsafe(32)}"
        signature = hmac.new(self.settings.token_hmac_key, b"refresh-sign:" + body.encode(), hashlib.sha256).hexdigest()
        return f"{body}.{signature}"

    def refresh_session_id(self, token: str) -> UUID | None:
        try:
            session_id, random_part, signature = token.split(".")
            if len(random_part) != 43 or len(signature) != 64:
                return None
            body = f"{session_id}.{random_part}"
            expected = hmac.new(self.settings.token_hmac_key, b"refresh-sign:" + body.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                return None
            return UUID(session_id)
        except (ValueError, TypeError):
            return None

    def refresh_digest(self, token: str) -> str:
        return hmac.new(self.settings.token_hmac_key, b"refresh-store:" + token.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def token_digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
