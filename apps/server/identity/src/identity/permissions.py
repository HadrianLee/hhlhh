from enum import StrEnum

from authz_helper.permission_types import Permission as BasePermission


class Permission(BasePermission, StrEnum):
    """Permissions enforced by the identity application."""

    __str__ = StrEnum.__str__

    USERS_READ = "identity.users.read"
    USERS_MANAGE = "identity.users.manage"
    ROLES_READ = "identity.roles.read"
    ROLES_MANAGE = "identity.roles.manage"
    PERMISSIONS_READ = "identity.permissions.read"
    PERMISSIONS_MANAGE = "identity.permissions.manage"
    AUDIT_READ = "identity.audit.read"
