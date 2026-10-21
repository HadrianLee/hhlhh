from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from authz_helper.mixins import CreatedAtMixin
from .base import IdentityBase
from .identity import UserSession


class ChallengePurpose(StrEnum):
    PASSKEY_REGISTRATION = "passkey_registration"
    PASSKEY_AUTHENTICATION = "passkey_authentication"
    EMAIL_OTP = "email_otp"


class AuthChallenge(CreatedAtMixin, IdentityBase):
    __tablename__ = "auth_challenges"
    __table_args__ = (
        CheckConstraint("purpose IN ('passkey_registration', 'passkey_authentication', 'email_otp')", name="purpose_allowed"),
        CheckConstraint("attempts_remaining BETWEEN 0 AND 5", name="attempts_allowed"),
        CheckConstraint(
            "(purpose = 'email_otp' AND otp_digest IS NOT NULL AND length(otp_digest) = 64 "
            "AND challenge IS NULL AND rp_id IS NULL AND origin IS NULL) OR "
            "(purpose <> 'email_otp' AND otp_digest IS NULL AND challenge IS NOT NULL "
            "AND length(challenge) >= 16 AND rp_id IS NOT NULL AND origin IS NOT NULL)",
            name="purpose_data_valid",
        ),
        Index("ix_auth_challenges_user_purpose_created", "user_id", "purpose", "created_at"),
        Index("ix_auth_challenges_session_verified", "session_id", "verified_at"),
        {"schema": "identity"},
    )

    challenge_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("identity.users.user_id", ondelete="CASCADE"), nullable=False)
    session_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey(f"{UserSession.__table__.fullname}.session_id", ondelete="CASCADE"), nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    challenge: Mapped[bytes | None] = mapped_column(LargeBinary)
    otp_digest: Mapped[str | None] = mapped_column(String(64))
    rp_id: Mapped[str | None] = mapped_column(String(253))
    origin: Mapped[str | None] = mapped_column(String(2048))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts_remaining: Mapped[int] = mapped_column(Integer, nullable=False, default=5, server_default="5")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Passkey(CreatedAtMixin, IdentityBase):
    __tablename__ = "passkeys"
    __table_args__ = (
        CheckConstraint("length(credential_id) BETWEEN 1 AND 1023", name="credential_id_length"),
        CheckConstraint("length(public_key) > 0", name="public_key_present"),
        CheckConstraint("sign_count BETWEEN 0 AND 4294967295", name="sign_count_allowed"),
        CheckConstraint("device_type IN ('single_device', 'multi_device')", name="device_type_allowed"),
        {"schema": "identity"},
    )

    credential_id: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    user_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("identity.users.user_id", ondelete="CASCADE"), nullable=False, index=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    rp_id: Mapped[str] = mapped_column(String(253), nullable=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    device_type: Mapped[str] = mapped_column(String(20), nullable=False)
    backed_up: Mapped[bool] = mapped_column(Boolean, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PasskeyLoginChallenge(CreatedAtMixin, IdentityBase):
    __tablename__ = "passkey_login_challenges"
    __table_args__ = (
        CheckConstraint("length(challenge) >= 16", name="challenge_length"),
        CheckConstraint("length(browser_binding) = 64", name="binding_length"),
        CheckConstraint("attempts_remaining BETWEEN 0 AND 5", name="attempts_allowed"),
        Index("ix_passkey_login_challenges_expires_at", "expires_at"),
        {"schema": "identity"},
    )

    challenge_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    challenge: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    browser_binding: Mapped[str] = mapped_column(String(64), nullable=False)
    rp_id: Mapped[str] = mapped_column(String(253), nullable=False)
    origin: Mapped[str] = mapped_column(String(2048), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts_remaining: Mapped[int] = mapped_column(Integer, nullable=False, default=5, server_default="5")
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
