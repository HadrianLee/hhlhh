from __future__ import annotations

from .base import IdentityBase as Base

from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from authz_helper.mixins import (
    CreatedAtMixin, 
    TimestampMixin, 
    RoleMixin,
    PermissionMixin,
    RolePermissionMixin,
    UserRoleMixin,
    RoleAuditLogMixin,
    RoleDefinitionAuditLogMixin,
    RolePermissionAuditLogMixin,
)

JSON_DOCUMENT = JSON().with_variant(JSONB, "postgresql")

def _fk(table: str, column: str) -> str:
    return f"{"identity"}.{table}.{column}"

class AuthTokenType(StrEnum):
    VERIFY_ACCOUNT = "verify_account"
    PASSWORD_RESET = "password_reset"


class RoleAuditAction(StrEnum):
    ASSIGNED = "role_assigned"
    REMOVED = "role_removed"


class RoleDefinitionAuditAction(StrEnum):
    CREATED = "role_created"
    UPDATED = "role_updated"
    DELETED = "role_deleted"


class RolePermissionAuditAction(StrEnum):
    ATTACHED = "permission_attached"
    REMOVED = "permission_removed"

class Role(Base, RoleMixin):
    __tablename__ = "roles"

class Permission(Base, PermissionMixin):
    __tablename__ = "permissions"


class RolePermission(Base, RolePermissionMixin):
    __tablename__ = "role_permissions"
    __role_fk_target__ = _fk("roles", "role_id")
    __permission_fk_target__ = _fk("permissions", "permission_id")

class User(TimestampMixin, Base):
    __tablename__ = "users"

    user_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    username: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_banned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class UserSecondaryEmail(CreatedAtMixin, Base):
    __tablename__ = "user_secondary_emails"
    __table_args__ = (
        UniqueConstraint("user_id", "email", name="uq_user_secondary_emails_user_email"),
    )

    secondary_email_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey(_fk("users", "user_id"), ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  

class AuthToken(CreatedAtMixin, Base):
    __tablename__ = "auth_tokens"
    __table_args__ = (
        CheckConstraint(
            "token_type in ('verify_account', 'password_reset')",
            name="token_type_allowed",
        ),
        CheckConstraint("length(token_digest) = 64", name="token_digest_sha256_hex"),
        Index("ix_auth_tokens_user_type", "user_id", "token_type"),
    )

    auth_token_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey(_fk("users", "user_id"), ondelete="CASCADE"),
        nullable=False,
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    token_type: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

class UserSession(CreatedAtMixin, Base):
    __tablename__ = "user_sessions"
    __table_args__ = (
        CheckConstraint(
            "length(refresh_token_digest) = 64",
            name="refresh_token_digest_hmac_sha256_hex",
        ),
        Index("ix_user_sessions_user_active", "user_id", "revoked_at", "expires_at"),
    )

    session_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey(_fk("users", "user_id"), ondelete="CASCADE"),
        nullable=False,
    )
    # Hex-encoded HMAC-SHA256(raw_refresh_token, server_side_hmac_key).
    # Never store the raw refresh token or the HMAC key in this table.
    refresh_token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class UserRole(UserRoleMixin, Base):
    __tablename__ = "user_roles"
    __user_fk_target__ = _fk("users", "user_id")
    __role_fk_target__ = _fk("roles", "role_id")

class RoleAuditLog(RoleAuditLogMixin, Base):
    __tablename__ = "role_audit_log"
    __user_fk_target__ = _fk("users", "user_id")
    __role_fk_target__ = _fk("roles", "role_id")

class RoleDefinitionAuditLog(RoleDefinitionAuditLogMixin, Base):
    __tablename__ = "role_definition_audit_log"
    __user_fk_target__ = _fk("users", "user_id")
    __role_fk_target__ = _fk("roles", "role_id")

class RolePermissionAuditLog(RolePermissionAuditLogMixin, Base):
    __tablename__ = "role_permission_audit_log"
    __user_fk_target__ = _fk("users", "user_id")
    __role_fk_target__ = _fk("roles", "role_id")
    __permission_fk_target__ = _fk("permissions", "permission_id")
