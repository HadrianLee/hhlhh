from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import ClassVar
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
from sqlalchemy.orm import Mapped, mapped_column, declared_attr

JSON_DOCUMENT = JSON().with_variant(JSONB, "postgresql")

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


class CreatedAtMixin:
    __abstract__ = True

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

class TimestampMixin(CreatedAtMixin):
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class RoleMixin:
    __abstract__ = True

    role_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")


class PermissionMixin:
    __abstract__ = True

    permission_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    action: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")


class RolePermissionMixin:
    __abstract__ = True

    __role_fk_target__: ClassVar[str]
    __permission_fk_target__: ClassVar[str]

    @declared_attr
    def role_id(cls) -> Mapped[UUID]:
        return mapped_column(Uuid, ForeignKey(cls.__role_fk_target__, ondelete="CASCADE"), primary_key=True)

    @declared_attr
    def permission_id(cls) -> Mapped[UUID]:
        return mapped_column(Uuid, ForeignKey(cls.__permission_fk_target__, ondelete="CASCADE"), primary_key=True)


class UserRoleMixin:
    __abstract__ = True

    __user_fk_target__: ClassVar[str]
    __role_fk_target__: ClassVar[str]

    @declared_attr
    def user_id(cls) -> Mapped[UUID]:
        return mapped_column(Uuid, ForeignKey(cls.__user_fk_target__, ondelete="CASCADE"), primary_key=True)

    @declared_attr
    def role_id(cls) -> Mapped[UUID]:
        return mapped_column(Uuid, ForeignKey(cls.__role_fk_target__, ondelete="CASCADE"), primary_key=True)

    @declared_attr
    def assigned_by_user_id(cls) -> Mapped[UUID | None]:
        return mapped_column(Uuid, ForeignKey(cls.__user_fk_target__, ondelete="SET NULL"), nullable=True)

    @declared_attr
    def assigned_at(cls) -> Mapped[datetime]:
        return mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class RoleAuditLogMixin(CreatedAtMixin):
    __abstract__ = True

    __user_fk_target__: ClassVar[str]
    __role_fk_target__: ClassVar[str]

    @declared_attr.directive
    def __table_args__(cls) -> tuple:
        table_args = getattr(super(), "__table_args__", ())
        if isinstance(table_args, dict):
            table_args = (table_args,)
        return (
            CheckConstraint(
                "action_type in ('role_assigned', 'role_removed')",
                name="action_type_allowed",
            ),
            *table_args,
        )

    role_audit_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)

    @declared_attr
    def actor_user_id(cls) -> Mapped[UUID]:
        return mapped_column(Uuid, ForeignKey(cls.__user_fk_target__), nullable=False)

    @declared_attr
    def target_user_id(cls) -> Mapped[UUID]:
        return mapped_column(Uuid, ForeignKey(cls.__user_fk_target__), nullable=False)

    action_type: Mapped[str] = mapped_column(String(32), nullable=False)

    @declared_attr
    def role_id(cls) -> Mapped[UUID | None]:
        return mapped_column(Uuid, ForeignKey(cls.__role_fk_target__, ondelete="SET NULL"), nullable=True)

    role_name_snapshot: Mapped[str] = mapped_column(String(100), nullable=False)
    changes: Mapped[dict] = mapped_column(JSON_DOCUMENT, nullable=False, default=dict, server_default="{}")


class RoleDefinitionAuditLogMixin(CreatedAtMixin):
    __abstract__ = True

    __user_fk_target__: ClassVar[str]
    __role_fk_target__: ClassVar[str]

    @declared_attr.directive
    def __table_args__(cls) -> tuple:
        table_args = getattr(super(), "__table_args__", ())
        if isinstance(table_args, dict):
            table_args = (table_args,)
        return (
            CheckConstraint(
                "action_type in ('role_created', 'role_updated', 'role_deleted')",
                name="action_type_allowed",
            ),
            *table_args,
        )

    role_definition_audit_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)

    @declared_attr
    def actor_user_id(cls) -> Mapped[UUID]:
        return mapped_column(Uuid, ForeignKey(cls.__user_fk_target__), nullable=False)

    action_type: Mapped[str] = mapped_column(String(32), nullable=False)

    @declared_attr
    def role_id(cls) -> Mapped[UUID | None]:
        return mapped_column(Uuid, ForeignKey(cls.__role_fk_target__, ondelete="SET NULL"), nullable=True)

    role_name_snapshot: Mapped[str] = mapped_column(String(100), nullable=False)
    changes: Mapped[dict] = mapped_column(JSON_DOCUMENT, nullable=False, default=dict, server_default="{}")


class RolePermissionAuditLogMixin(CreatedAtMixin):
    __abstract__ = True
    __tablename__ = "role_permission_audit_log"

    __user_fk_target__: ClassVar[str]
    __role_fk_target__: ClassVar[str]
    __permission_fk_target__: ClassVar[str]

    @declared_attr.directive
    def __table_args__(cls) -> tuple:
        table_args = getattr(super(), "__table_args__", ())
        if isinstance(table_args, dict):
            table_args = (table_args,)
        return (
            CheckConstraint(
                "action_type in ('permission_attached', 'permission_removed')",
                name="action_type_allowed",
            ),
            *table_args,
        )

    role_permission_audit_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)

    @declared_attr
    def actor_user_id(cls) -> Mapped[UUID]:
        return mapped_column(Uuid, ForeignKey(cls.__user_fk_target__), nullable=False)

    action_type: Mapped[str] = mapped_column(String(40), nullable=False)

    @declared_attr
    def role_id(cls) -> Mapped[UUID | None]:
        return mapped_column(Uuid, ForeignKey(cls.__role_fk_target__, ondelete="SET NULL"), nullable=True)

    role_name_snapshot: Mapped[str] = mapped_column(String(100), nullable=False)

    @declared_attr
    def permission_id(cls) -> Mapped[UUID | None]:
        return mapped_column(Uuid, ForeignKey(cls.__permission_fk_target__, ondelete="SET NULL"), nullable=True)

    permission_action_snapshot: Mapped[str] = mapped_column(String(160), nullable=False)
    changes: Mapped[dict] = mapped_column(JSON_DOCUMENT, nullable=False, default=dict, server_default="{}")
