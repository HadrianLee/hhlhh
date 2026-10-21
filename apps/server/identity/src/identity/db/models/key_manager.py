from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, String, Text, column, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import KeyManagerBase


class PublicKey(KeyManagerBase):
    """One public RSA JWK for the application's RS256 JWT profile."""

    __tablename__ = "jwks"
    __table_args__ = (
        CheckConstraint("length(kid) BETWEEN 1 AND 128 AND kid = trim(kid)", name="kid_valid"),
        CheckConstraint("kty = 'RSA'", name="kty_rsa"),
        CheckConstraint('"use" = \'sig\'', name="use_sig"),
        CheckConstraint("alg = 'RS256'", name="alg_rs256"),
        CheckConstraint("length(n) >= 342 AND length(n) % 4 != 1", name="n_length"),
        CheckConstraint("length(e) > 0 AND length(e) % 4 != 1", name="e_length"),
        CheckConstraint(~column("n").regexp_match(r"[^A-Za-z0-9_-]"), name="n_base64url"),
        CheckConstraint(~column("e").regexp_match(r"[^A-Za-z0-9_-]"), name="e_base64url"),
        dict(KeyManagerBase.__table_args__),
    )

    kid: Mapped[str] = mapped_column(String(128), primary_key=True)
    kty: Mapped[str] = mapped_column(String(8), nullable=False, default="RSA", server_default="RSA")
    use: Mapped[str] = mapped_column(String(3), nullable=False, default="sig", server_default="sig")
    alg: Mapped[str] = mapped_column(String(16), nullable=False, default="RS256", server_default="RS256")
    n: Mapped[str] = mapped_column(Text, nullable=False)
    e: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def public_jwk(self) -> dict[str, str]:
        return {
            "kty": self.kty,
            "use": self.use,
            "alg": self.alg,
            "kid": self.kid,
            "n": self.n,
            "e": self.e,
        }
