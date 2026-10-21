from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, LargeBinary, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import BffBase


class SessionEventType(StrEnum):
    CREATED = "created"
    REFRESHED = "refreshed"
    REVOKED = "revoked"
    IDENTITY_REVOKED = "identity_revoked"


class BrowserSession(BffBase):
    __tablename__ = "browser_sessions"
    __table_args__ = (
        CheckConstraint("length(cookie_digest) = 64", name="cookie_digest_length"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        CheckConstraint("last_used_at >= created_at", name="last_used_after_creation"),
        CheckConstraint("(access_token_encrypted IS NULL) = (refresh_token_encrypted IS NULL)", name="token_pair"),
        CheckConstraint("revoked_at IS NOT NULL OR access_token_encrypted IS NOT NULL", name="active_tokens_present"),
        CheckConstraint("NOT revocation_pending OR revoked_at IS NOT NULL", name="pending_is_revoked"),
        Index("ix_browser_sessions_user_active", "user_id", "revoked_at", "expires_at"),
        Index("ix_browser_sessions_cleanup", "revocation_pending", "last_used_at"),
        {"schema": "bff"},
    )

    session_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    # These UUIDs refer to identity; BFF has no cross-service foreign keys or user table.
    user_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    identity_session_id: Mapped[UUID] = mapped_column(Uuid, nullable=False, unique=True)
    cookie_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    access_token_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    refresh_token_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    access_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    refresh_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(64))
    revocation_pending: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))


class SessionEvent(BffBase):
    __tablename__ = "session_events"
    __table_args__ = (
        CheckConstraint("event_type IN ('created', 'refreshed', 'revoked', 'identity_revoked')", name="event_type_allowed"),
        Index("ix_session_events_session_created", "session_id", "created_at"),
        {"schema": "bff"},
    )

    event_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("bff.browser_sessions.session_id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
