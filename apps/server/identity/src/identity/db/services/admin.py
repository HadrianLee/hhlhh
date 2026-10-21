from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..errors import IdentityConflictError, IdentityNotFoundError, IdentityPolicyError
from ..models.identity import (
    Permission, Role, RoleDefinitionAuditAction, RoleDefinitionAuditLog,
    RolePermission, RolePermissionAuditAction, RolePermissionAuditLog, RoleAuditLog, User,
)
from .base import Database
from .security import require_recent_mfa


class IdentityAdminDbService:
    def __init__(self, database: Database) -> None:
        self.db = database

    async def list_users(self, *, limit: int, offset: int) -> list[User]:
        async with self.db.session() as session:
            return list(await session.scalars(select(User).order_by(User.created_at.desc(), User.user_id)
                .limit(limit).offset(offset)))

    async def list_roles(self, *, limit: int, offset: int) -> list[Role]:
        async with self.db.session() as session:
            return list(await session.scalars(select(Role).order_by(Role.name).limit(limit).offset(offset)))

    async def get_role(self, role_id: UUID) -> Role:
        async with self.db.session() as session:
            role = await session.get(Role, role_id)
            if role is None:
                raise IdentityNotFoundError("role not found")
            return role

    async def create_role(self, *, actor_user_id: UUID, actor_session_id: UUID, name: str, description: str) -> Role:
        try:
            async with self.db.transaction() as session:
                await require_recent_mfa(session, actor_user_id, actor_session_id)
                role = Role(name=name, description=description)
                session.add(role)
                await session.flush()
                session.add(RoleDefinitionAuditLog(
                    actor_user_id=actor_user_id, action_type=RoleDefinitionAuditAction.CREATED.value,
                    role_id=role.role_id, role_name_snapshot=role.name,
                    changes={"name": role.name, "description": role.description},
                ))
                return role
        except IntegrityError as exc:
            raise IdentityConflictError("role name already exists") from exc

    async def update_role(self, role_id: UUID, *, actor_user_id: UUID, actor_session_id: UUID, changes: dict) -> Role:
        try:
            async with self.db.transaction() as session:
                await require_recent_mfa(session, actor_user_id, actor_session_id)
                role = await session.get(Role, role_id, with_for_update=True)
                if role is None:
                    raise IdentityNotFoundError("role not found")
                if role.is_system:
                    raise IdentityPolicyError("system roles cannot be modified")
                audit_changes = {}
                for field in ("name", "description"):
                    if field in changes and changes[field] != getattr(role, field):
                        audit_changes[field] = {"old": getattr(role, field), "new": changes[field]}
                        setattr(role, field, changes[field])
                if audit_changes:
                    session.add(RoleDefinitionAuditLog(
                        actor_user_id=actor_user_id, action_type=RoleDefinitionAuditAction.UPDATED.value,
                        role_id=role.role_id, role_name_snapshot=role.name, changes=audit_changes,
                    ))
                await session.flush()
                return role
        except IntegrityError as exc:
            raise IdentityConflictError("role name already exists") from exc

    async def delete_role(self, role_id: UUID, *, actor_user_id: UUID, actor_session_id: UUID) -> None:
        async with self.db.transaction() as session:
            await require_recent_mfa(session, actor_user_id, actor_session_id)
            role = await session.get(Role, role_id, with_for_update=True)
            if role is None:
                raise IdentityNotFoundError("role not found")
            if role.is_system:
                raise IdentityPolicyError("system roles cannot be deleted")
            session.add(RoleDefinitionAuditLog(
                actor_user_id=actor_user_id, action_type=RoleDefinitionAuditAction.DELETED.value,
                role_id=None, role_name_snapshot=role.name, changes={"deleted": True},
            ))
            await session.delete(role)

    async def list_permissions(self, *, limit: int, offset: int) -> list[Permission]:
        async with self.db.session() as session:
            return list(await session.scalars(select(Permission).order_by(Permission.action).limit(limit).offset(offset)))

    async def get_permission(self, permission_id: UUID) -> Permission:
        async with self.db.session() as session:
            permission = await session.get(Permission, permission_id)
            if permission is None:
                raise IdentityNotFoundError("permission not found")
            return permission

    async def create_permission(self, *, actor_user_id: UUID, actor_session_id: UUID, action: str, description: str) -> Permission:
        try:
            async with self.db.transaction() as session:
                await require_recent_mfa(session, actor_user_id, actor_session_id)
                permission = Permission(action=action, description=description)
                session.add(permission)
                await session.flush()
                return permission
        except IntegrityError as exc:
            raise IdentityConflictError("permission action already exists") from exc

    async def update_permission(
        self, permission_id: UUID, *, actor_user_id: UUID, actor_session_id: UUID, changes: dict,
    ) -> Permission:
        try:
            async with self.db.transaction() as session:
                await require_recent_mfa(session, actor_user_id, actor_session_id)
                permission = await session.get(Permission, permission_id, with_for_update=True)
                if permission is None:
                    raise IdentityNotFoundError("permission not found")
                if "action" in changes and changes["action"] != permission.action:
                    system_role = await session.scalar(select(Role.role_id)
                        .join(RolePermission, RolePermission.role_id == Role.role_id)
                        .where(RolePermission.permission_id == permission_id, Role.is_system.is_(True)).limit(1))
                    if system_role is not None:
                        raise IdentityPolicyError("system role permissions cannot be renamed")
                for field in ("action", "description"):
                    if field in changes:
                        setattr(permission, field, changes[field])
                await session.flush()
                return permission
        except IntegrityError as exc:
            raise IdentityConflictError("permission action already exists") from exc

    async def delete_permission(self, permission_id: UUID, *, actor_user_id: UUID, actor_session_id: UUID) -> None:
        async with self.db.transaction() as session:
            await require_recent_mfa(session, actor_user_id, actor_session_id)
            permission = await session.get(Permission, permission_id, with_for_update=True)
            if permission is None:
                raise IdentityNotFoundError("permission not found")
            system_role = await session.scalar(select(Role.role_id)
                .join(RolePermission, RolePermission.role_id == Role.role_id)
                .where(RolePermission.permission_id == permission_id, Role.is_system.is_(True)).limit(1))
            if system_role is not None:
                raise IdentityPolicyError("system role permissions cannot be deleted")
            roles = await session.scalars(select(Role).join(RolePermission, RolePermission.role_id == Role.role_id)
                .where(RolePermission.permission_id == permission_id))
            for role in roles:
                session.add(RolePermissionAuditLog(
                    actor_user_id=actor_user_id, action_type=RolePermissionAuditAction.REMOVED.value,
                    role_id=role.role_id, role_name_snapshot=role.name,
                    permission_id=None, permission_action_snapshot=permission.action, changes={"permission_deleted": True},
                ))
            await session.delete(permission)

    async def list_user_roles(self, user_id: UUID, *, limit: int, offset: int) -> list[Role]:
        from ..models.identity import UserRole

        async with self.db.session() as session:
            if await session.get(User, user_id) is None:
                raise IdentityNotFoundError("user not found")
            return list(await session.scalars(select(Role).join(UserRole, UserRole.role_id == Role.role_id)
                .where(UserRole.user_id == user_id).order_by(Role.name).limit(limit).offset(offset)))

    async def list_role_permissions(self, role_id: UUID, *, limit: int, offset: int) -> list[Permission]:
        async with self.db.session() as session:
            if await session.get(Role, role_id) is None:
                raise IdentityNotFoundError("role not found")
            return list(await session.scalars(select(Permission)
                .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
                .where(RolePermission.role_id == role_id).order_by(Permission.action).limit(limit).offset(offset)))

    async def set_role_permission(
        self, role_id: UUID, permission_id: UUID, *, actor_user_id: UUID, actor_session_id: UUID, attached: bool,
    ) -> bool:
        async with self.db.transaction() as session:
            await require_recent_mfa(session, actor_user_id, actor_session_id)
            role = await session.get(Role, role_id, with_for_update=True)
            permission = await session.get(Permission, permission_id)
            if role is None or permission is None:
                raise IdentityNotFoundError("role or permission not found")
            if role.is_system:
                raise IdentityPolicyError("system roles cannot be modified")
            membership = await session.get(RolePermission, (role_id, permission_id))
            if (membership is not None) == attached:
                return False
            if attached:
                session.add(RolePermission(role_id=role_id, permission_id=permission_id))
            else:
                await session.delete(membership)
            session.add(RolePermissionAuditLog(
                actor_user_id=actor_user_id,
                action_type=(RolePermissionAuditAction.ATTACHED if attached else RolePermissionAuditAction.REMOVED).value,
                role_id=role_id, role_name_snapshot=role.name,
                permission_id=permission_id, permission_action_snapshot=permission.action,
                changes={"attached": attached},
            ))
            return True

    async def list_role_audits(self, *, limit: int, offset: int) -> list[RoleAuditLog]:
        async with self.db.session() as session:
            return list(await session.scalars(select(RoleAuditLog)
                .order_by(RoleAuditLog.created_at.desc(), RoleAuditLog.role_audit_id).limit(limit).offset(offset)))

    async def list_definition_audits(self, *, limit: int, offset: int) -> list[RoleDefinitionAuditLog]:
        async with self.db.session() as session:
            return list(await session.scalars(select(RoleDefinitionAuditLog)
                .order_by(RoleDefinitionAuditLog.created_at.desc(), RoleDefinitionAuditLog.role_definition_audit_id)
                .limit(limit).offset(offset)))

    async def list_permission_audits(self, *, limit: int, offset: int) -> list[RolePermissionAuditLog]:
        async with self.db.session() as session:
            return list(await session.scalars(select(RolePermissionAuditLog)
                .order_by(RolePermissionAuditLog.created_at.desc(), RolePermissionAuditLog.role_permission_audit_id)
                .limit(limit).offset(offset)))
