"""Trusted operator command to grant identity-local administration to an existing user."""
import argparse
import asyncio
from uuid import UUID

from sqlalchemy import select

from identity.db.models.identity import (
    Permission, Role, RoleAuditAction, RoleAuditLog, RoleDefinitionAuditAction,
    RoleDefinitionAuditLog, RolePermission, RolePermissionAuditAction,
    RolePermissionAuditLog, User, UserRole,
)
from identity.db.services.base import Database

ADMIN_PERMISSIONS = (
    "identity.users.read", "identity.users.manage", "identity.roles.read", "identity.roles.manage",
    "identity.permissions.read", "identity.permissions.manage", "identity.audit.read",
)


async def grant_admin(user_id: UUID, database: Database | None = None) -> None:
    database = database if database is not None else Database()
    async with database.transaction() as session:
        user = await session.get(User, user_id, with_for_update=True)
        if user is None or user.is_banned:
            raise ValueError("an existing, active user is required")
        role = await session.scalar(select(Role).where(Role.name == "identity-admin").with_for_update())
        if role is None:
            role = Role(name="identity-admin", description="Identity service administration", is_system=True)
            session.add(role)
            await session.flush()
            session.add(RoleDefinitionAuditLog(
                actor_user_id=user_id, action_type=RoleDefinitionAuditAction.CREATED.value,
                role_id=role.role_id, role_name_snapshot=role.name, changes={"bootstrap": True},
            ))
        elif not role.is_system:
            raise ValueError("identity-admin already exists as a non-system role")
        for action in ADMIN_PERMISSIONS:
            permission = await session.scalar(select(Permission).where(Permission.action == action))
            if permission is None:
                permission = Permission(action=action)
                session.add(permission)
                await session.flush()
            if await session.get(RolePermission, (role.role_id, permission.permission_id)) is None:
                session.add(RolePermission(role_id=role.role_id, permission_id=permission.permission_id))
                session.add(RolePermissionAuditLog(
                    actor_user_id=user_id, action_type=RolePermissionAuditAction.ATTACHED.value,
                    role_id=role.role_id, role_name_snapshot=role.name,
                    permission_id=permission.permission_id, permission_action_snapshot=permission.action,
                    changes={"bootstrap": True},
                ))
        if await session.get(UserRole, (user_id, role.role_id)) is None:
            session.add(UserRole(user_id=user_id, role_id=role.role_id, assigned_by_user_id=user_id))
            session.add(RoleAuditLog(
                actor_user_id=user_id, target_user_id=user_id, action_type=RoleAuditAction.ASSIGNED.value,
                role_id=role.role_id, role_name_snapshot=role.name, changes={"bootstrap": True},
            ))
            user.token_version += 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-id", required=True, type=UUID)
    args = parser.parse_args()
    asyncio.run(grant_admin(args.user_id))
    print("Identity administrator role granted.")


if __name__ == "__main__":
    main()
