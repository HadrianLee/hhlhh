from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Mapping
from datetime import UTC, datetime
import re
from typing import Any

from joserfc.errors import JoseError
from joserfc.jwk import RSAKey
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from ..errors import IdentityConflictError
from ..models.key_manager import PublicKey
from .base import Database


def _utc_datetime(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _validate_kid(kid: str) -> str:
    if not isinstance(kid, str) or not kid or len(kid) > 128 or kid != kid.strip():
        raise ValueError("kid must contain 1 to 128 characters without surrounding whitespace")
    return kid


def _public_jwk(public_jwk: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(public_jwk, Mapping):
        raise ValueError("public_jwk must be a JWK mapping")
    if {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}.intersection(public_jwk):
        raise ValueError("public_jwk must not contain private key material")
    if public_jwk.get("kty") != "RSA":
        raise ValueError("public_jwk must be an RSA key")
    if public_jwk.get("alg", "RS256") != "RS256":
        raise ValueError("public_jwk must use RS256")
    if public_jwk.get("use", "sig") != "sig":
        raise ValueError("public_jwk must be a signature key")
    if public_jwk.get("key_ops", ["verify"]) != ["verify"]:
        raise ValueError("public_jwk key_ops must allow verification only")

    kid = _validate_kid(public_jwk.get("kid"))
    for field_name in ("n", "e"):
        value = public_jwk.get(field_name)
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
            or len(value) % 4 == 1
        ):
            raise ValueError(f"public_jwk {field_name} must be an unpadded base64url integer")
        decoded = urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if decoded[0] == 0 or urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
            raise ValueError(f"public_jwk {field_name} must use the minimal base64url integer encoding")

    try:
        key = RSAKey.import_key({name: public_jwk[name] for name in ("kty", "n", "e")})
    except (JoseError, KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError("public_jwk contains an invalid RSA public key") from exc
    if key.raw_value.key_size < 2048:
        raise ValueError("RSA public keys must contain at least 2048 bits")

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": public_jwk["n"],
        "e": public_jwk["e"],
    }


class KeyManagerDbService:
    """Persist public verification keys; private signing keys stay in the caller.

    expires_at must cover the last token signed with the key plus verifier leeway.
    A key id is immutable: publishing an existing kid raises a conflict.
    """

    def __init__(self, database: Database) -> None:
        self.db = database

    async def publish_key(
        self,
        *,
        public_jwk: Mapping[str, Any],
        expires_at: datetime,
    ) -> None:
        public_jwk = _public_jwk(public_jwk)
        expires_at = _utc_datetime(expires_at, field_name="expires_at")
        if expires_at <= datetime.now(UTC):
            raise ValueError("expires_at must be in the future")

        try:
            async with self.db.transaction() as session:
                session.add(PublicKey(
                    kid=public_jwk["kid"],
                    kty=public_jwk["kty"],
                    use=public_jwk["use"],
                    alg=public_jwk["alg"],
                    n=public_jwk["n"],
                    e=public_jwk["e"],
                    expires_at=expires_at,
                ))
                await session.flush()
        except IntegrityError as exc:
            raise IdentityConflictError("public key id already exists") from exc

    async def get_public_key(
        self,
        kid: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, str] | None:
        kid = _validate_kid(kid)
        now = _utc_datetime(now, field_name="now") if now is not None else datetime.now(UTC)
        async with self.db.session() as session:
            key = await session.scalar(
                select(PublicKey).where(
                    PublicKey.kid == kid,
                    PublicKey.revoked_at.is_(None),
                    PublicKey.expires_at > now,
                )
            )
            return key.public_jwk if key is not None else None

    async def jwks(self, *, now: datetime | None = None) -> dict[str, list[dict[str, str]]]:
        now = _utc_datetime(now, field_name="now") if now is not None else datetime.now(UTC)
        async with self.db.session() as session:
            keys = await session.scalars(
                select(PublicKey)
                .where(
                    PublicKey.revoked_at.is_(None),
                    PublicKey.expires_at > now,
                )
                .order_by(PublicKey.created_at, PublicKey.kid)
            )
            return {"keys": [key.public_jwk for key in keys]}

    async def revoke_key(self, kid: str, *, now: datetime | None = None) -> bool:
        kid = _validate_kid(kid)
        now = _utc_datetime(now, field_name="now") if now is not None else datetime.now(UTC)
        async with self.db.transaction() as session:
            result = await session.execute(
                update(PublicKey)
                .where(PublicKey.kid == kid, PublicKey.revoked_at.is_(None))
                .values(revoked_at=now)
                .returning(PublicKey.kid)
            )
            return result.scalar_one_or_none() is not None

    async def delete_expired_keys(self, *, now: datetime | None = None) -> int:
        now = _utc_datetime(now, field_name="now") if now is not None else datetime.now(UTC)
        async with self.db.transaction() as session:
            result = await session.execute(
                delete(PublicKey)
                .where(PublicKey.expires_at <= now)
                .returning(PublicKey.kid)
            )
            return len(result.scalars().all())
