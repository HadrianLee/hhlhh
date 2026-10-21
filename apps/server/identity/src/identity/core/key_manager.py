from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import logging
import os
import time
from typing import Any
import uuid
from threading import RLock
from joserfc import jwt
from joserfc.jwk import RSAKey

from identity.db.services.key_manager import KeyManagerDbService

JWT_ACCESS_TOKEN_TTL_SECONDS = int(os.environ["JWT_ACCESS_TOKEN_TTL_SECONDS"])
JWT_KEY_ROTATION_INTERVAL_SECONDS = int(os.environ["JWT_KEY_ROTATION_INTERVAL_SECONDS"])
JWT_CLOCK_SKEW_SECONDS = int(os.environ.get("JWT_CLOCK_SKEW_SECONDS", "5"))
ISSUER = os.environ["JWT_ISSUER"]
AUDIENCE = os.environ["JWT_AUDIENCE"]

logger = logging.getLogger(__name__)

class KeyManager:
    def __init__(self, database: KeyManagerDbService) -> None:
        if JWT_ACCESS_TOKEN_TTL_SECONDS <= 0 or JWT_KEY_ROTATION_INTERVAL_SECONDS <= 0:
            raise ValueError("JWT token lifetime and key rotation interval must be positive")
        if JWT_CLOCK_SKEW_SECONDS < 0:
            raise ValueError("JWT_CLOCK_SKEW_SECONDS must be nonnegative")
        if not ISSUER.strip() or not AUDIENCE.strip():
            raise ValueError("JWT_ISSUER and JWT_AUDIENCE must not be blank")

        self.db = database
        self._lock = RLock()
        self._rotation_lock = asyncio.Lock()
        self._active: RSAKey | None = None
        self._active_expires_at: datetime | None = None

    async def rotate(self) -> None:
        async with self._rotation_lock:
            key = await asyncio.to_thread(
                RSAKey.generate_key,
                2048,
                {"use": "sig", "alg": "RS256", "kid": uuid.uuid4().hex},
            )
            expires_at = datetime.now(UTC) + timedelta(
                seconds=(
                    JWT_KEY_ROTATION_INTERVAL_SECONDS
                    + JWT_ACCESS_TOKEN_TTL_SECONDS
                    + JWT_CLOCK_SKEW_SECONDS
                ),
            )
            await self.db.publish_key(
                public_jwk=key.as_dict(private=False),
                expires_at=expires_at,
            )

            with self._lock:
                self._active = key
                self._active_expires_at = expires_at

            try:
                await self.db.delete_expired_keys()
            except Exception:
                logger.exception("Unable to delete expired public JWKs")

    def sign(self, payload: dict[str, Any]) -> str:
        """Sign identity claims after the caller has authenticated the user."""
        if not isinstance(payload, dict) or set(payload) - {"sub", "sid"}:
            raise ValueError("access tokens only accept sub and optional sid identity claims")
        for name in ("sub", "sid"):
            if name == "sub" or name in payload:
                value = payload.get(name)
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"{name} must be a nonempty string")

        with self._lock:
            key = self._active
            if key is None or self._active_expires_at is None:
                raise RuntimeError("the key manager must rotate before signing tokens")
            now = int(time.time())
            if now + JWT_ACCESS_TOKEN_TTL_SECONDS + JWT_CLOCK_SKEW_SECONDS > self._active_expires_at.timestamp():
                raise RuntimeError("the active signing key is overdue for rotation")

            claims = {
                **payload,
                "iat": now,
                "nbf": now,
                "exp": now + JWT_ACCESS_TOKEN_TTL_SECONDS,
                "iss": ISSUER,
                "aud": AUDIENCE,
                "jti": uuid.uuid4().hex,
            }
            return jwt.encode(
                {
                    "alg": "RS256",
                    "kid": key.kid,
                    "typ": "JWT",
                },
                claims,
                key,
                algorithms=["RS256"],
            )

    async def jwks(self) -> dict[str, list[dict[str, str]]]:
        return await self.db.jwks()
