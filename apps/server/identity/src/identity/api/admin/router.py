from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from identity.api.admin.schemas import (
    AdminUserResponse, BanRequest, ChangedResponse, DefinitionAuditResponse,
    PermissionAuditResponse, PermissionCreateRequest, PermissionResponse, PermissionUpdateRequest,
    RoleAuditResponse, RoleCreateRequest, RoleResponse, RoleUpdateRequest,
)
from identity.api.auth.schemas import SessionResponse
from identity.api.challenges.dependencies import require_permission_with_mfa
from identity.api.challenges.problems import RECENT_MFA_RESPONSES
from identity.api.dependencies import DatabaseDep, Principal, require_permission
from identity.db.errors import IdentityNotFoundError, IdentityPolicyError
from identity.db.services.admin import IdentityAdminDbService
from identity.permissions import Permission

router = APIRouter()


def get_admin_database(request: Request) -> IdentityAdminDbService:
    return IdentityAdminDbService(request.app.state.identity_db.db)


AdminDb = Annotated[IdentityAdminDbService, Depends(get_admin_database)]
ReadUsers = Annotated[Principal, Depends(require_permission(Permission.USERS_READ))]
ManageUsers = Annotated[Principal, Depends(require_permission_with_mfa(Permission.USERS_MANAGE))]
ReadRoles = Annotated[Principal, Depends(require_permission(Permission.ROLES_READ))]
ManageRoles = Annotated[Principal, Depends(require_permission_with_mfa(Permission.ROLES_MANAGE))]
ReadPermissions = Annotated[Principal, Depends(require_permission(Permission.PERMISSIONS_READ))]
ManagePermissions = Annotated[Principal, Depends(require_permission_with_mfa(Permission.PERMISSIONS_MANAGE))]
ReadAudit = Annotated[Principal, Depends(require_permission(Permission.AUDIT_READ))]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]


@router.get("/users", response_model=list[AdminUserResponse], tags=["identity administration"])
async def users(principal: ReadUsers, database: AdminDb, limit: Limit = 50, offset: Offset = 0):
    return await database.list_users(limit=limit, offset=offset)


@router.get("/users/{user_id}", response_model=AdminUserResponse, tags=["identity administration"])
async def user(user_id: UUID, principal: ReadUsers, database: DatabaseDep):
    result = await database.get_user(user_id)
    if result is None:
        raise IdentityNotFoundError("user not found")
    return result


@router.patch("/users/{user_id}/ban", response_model=AdminUserResponse, tags=["identity administration"], responses=RECENT_MFA_RESPONSES)
async def ban_user(user_id: UUID, request: BanRequest, principal: ManageUsers, database: DatabaseDep):
    if principal.user.user_id == user_id and request.is_banned:
        raise IdentityPolicyError("administrators cannot ban their own account")
    return await database.set_user_banned(user_id=user_id, is_banned=request.is_banned,
        actor_user_id=principal.user.user_id, actor_session_id=principal.session.session_id)


@router.get("/users/{user_id}/sessions", response_model=list[SessionResponse], tags=["identity administration"])
async def user_sessions(user_id: UUID, principal: ReadUsers, database: DatabaseDep, limit: Limit = 50, offset: Offset = 0):
    if await database.get_user(user_id) is None:
        raise IdentityNotFoundError("user not found")
    return await database.list_sessions(user_id, limit=limit, offset=offset)


@router.delete("/users/{user_id}/sessions", status_code=204, tags=["identity administration"], responses=RECENT_MFA_RESPONSES)
async def revoke_user_sessions(user_id: UUID, principal: ManageUsers, database: DatabaseDep) -> Response:
    if await database.get_user(user_id) is None:
        raise IdentityNotFoundError("user not found")
    await database.revoke_all_user_sessions(user_id, actor_user_id=principal.user.user_id,
        actor_session_id=principal.session.session_id)
    return Response(status_code=204)


@router.get("/users/{user_id}/roles", response_model=list[RoleResponse], tags=["identity administration"])
async def user_roles(user_id: UUID, principal: ReadUsers, database: AdminDb, limit: Limit = 50, offset: Offset = 0):
    return await database.list_user_roles(user_id, limit=limit, offset=offset)


@router.get("/users/{user_id}/permissions", response_model=list[str], tags=["identity administration"])
async def user_permissions(user_id: UUID, principal: ReadUsers, database: DatabaseDep):
    if await database.get_user(user_id) is None:
        raise IdentityNotFoundError("user not found")
    return sorted(await database.list_user_permissions(user_id))


@router.put("/users/{user_id}/roles/{role_id}", response_model=ChangedResponse, tags=["identity administration"], responses=RECENT_MFA_RESPONSES)
async def assign_role(user_id: UUID, role_id: UUID, principal: ManageRoles, database: DatabaseDep):
    return {"changed": await database.assign_role(user_id=user_id, role_id=role_id,
        actor_user_id=principal.user.user_id, actor_session_id=principal.session.session_id)}


@router.delete("/users/{user_id}/roles/{role_id}", response_model=ChangedResponse, tags=["identity administration"], responses=RECENT_MFA_RESPONSES)
async def remove_role(user_id: UUID, role_id: UUID, principal: ManageRoles, database: DatabaseDep):
    return {"changed": await database.remove_role(user_id=user_id, role_id=role_id,
        actor_user_id=principal.user.user_id, actor_session_id=principal.session.session_id)}


@router.get("/roles", response_model=list[RoleResponse], tags=["identity roles"])
async def roles(principal: ReadRoles, database: AdminDb, limit: Limit = 50, offset: Offset = 0):
    return await database.list_roles(limit=limit, offset=offset)


@router.post("/roles", response_model=RoleResponse, status_code=201, tags=["identity roles"], responses=RECENT_MFA_RESPONSES)
async def create_role(request: RoleCreateRequest, principal: ManageRoles, database: AdminDb):
    return await database.create_role(actor_user_id=principal.user.user_id,
        actor_session_id=principal.session.session_id, **request.model_dump())


@router.get("/roles/{role_id}", response_model=RoleResponse, tags=["identity roles"])
async def role(role_id: UUID, principal: ReadRoles, database: AdminDb):
    return await database.get_role(role_id)


@router.patch("/roles/{role_id}", response_model=RoleResponse, tags=["identity roles"], responses=RECENT_MFA_RESPONSES)
async def update_role(role_id: UUID, request: RoleUpdateRequest, principal: ManageRoles, database: AdminDb):
    return await database.update_role(role_id, actor_user_id=principal.user.user_id,
        actor_session_id=principal.session.session_id, changes=request.model_dump(exclude_unset=True))


@router.delete("/roles/{role_id}", status_code=204, tags=["identity roles"], responses=RECENT_MFA_RESPONSES)
async def delete_role(role_id: UUID, principal: ManageRoles, database: AdminDb) -> Response:
    await database.delete_role(role_id, actor_user_id=principal.user.user_id,
        actor_session_id=principal.session.session_id)
    return Response(status_code=204)


@router.get("/roles/{role_id}/permissions", response_model=list[PermissionResponse], tags=["identity roles"])
async def role_permissions(role_id: UUID, principal: ReadRoles, database: AdminDb, limit: Limit = 50, offset: Offset = 0):
    return await database.list_role_permissions(role_id, limit=limit, offset=offset)


@router.put("/roles/{role_id}/permissions/{permission_id}", response_model=ChangedResponse, tags=["identity roles"], responses=RECENT_MFA_RESPONSES)
async def attach_permission(role_id: UUID, permission_id: UUID, principal: ManageRoles, database: AdminDb):
    return {"changed": await database.set_role_permission(role_id, permission_id,
        actor_user_id=principal.user.user_id, actor_session_id=principal.session.session_id, attached=True)}


@router.delete("/roles/{role_id}/permissions/{permission_id}", response_model=ChangedResponse, tags=["identity roles"], responses=RECENT_MFA_RESPONSES)
async def detach_permission(role_id: UUID, permission_id: UUID, principal: ManageRoles, database: AdminDb):
    return {"changed": await database.set_role_permission(role_id, permission_id,
        actor_user_id=principal.user.user_id, actor_session_id=principal.session.session_id, attached=False)}


@router.get("/permissions", response_model=list[PermissionResponse], tags=["identity permissions"])
async def permissions(principal: ReadPermissions, database: AdminDb, limit: Limit = 50, offset: Offset = 0):
    return await database.list_permissions(limit=limit, offset=offset)


@router.post("/permissions", response_model=PermissionResponse, status_code=201, tags=["identity permissions"], responses=RECENT_MFA_RESPONSES)
async def create_permission(request: PermissionCreateRequest, principal: ManagePermissions, database: AdminDb):
    return await database.create_permission(actor_user_id=principal.user.user_id,
        actor_session_id=principal.session.session_id, **request.model_dump())


@router.get("/permissions/{permission_id}", response_model=PermissionResponse, tags=["identity permissions"])
async def permission(permission_id: UUID, principal: ReadPermissions, database: AdminDb):
    return await database.get_permission(permission_id)


@router.patch("/permissions/{permission_id}", response_model=PermissionResponse, tags=["identity permissions"], responses=RECENT_MFA_RESPONSES)
async def update_permission(permission_id: UUID, request: PermissionUpdateRequest, principal: ManagePermissions, database: AdminDb):
    return await database.update_permission(permission_id, actor_user_id=principal.user.user_id,
        actor_session_id=principal.session.session_id, changes=request.model_dump(exclude_unset=True))


@router.delete("/permissions/{permission_id}", status_code=204, tags=["identity permissions"], responses=RECENT_MFA_RESPONSES)
async def delete_permission(permission_id: UUID, principal: ManagePermissions, database: AdminDb) -> Response:
    await database.delete_permission(permission_id, actor_user_id=principal.user.user_id,
        actor_session_id=principal.session.session_id)
    return Response(status_code=204)


@router.get("/audit/role-assignments", response_model=list[RoleAuditResponse], tags=["identity audit"])
async def role_audits(principal: ReadAudit, database: AdminDb, limit: Limit = 50, offset: Offset = 0):
    return await database.list_role_audits(limit=limit, offset=offset)


@router.get("/audit/role-definitions", response_model=list[DefinitionAuditResponse], tags=["identity audit"])
async def definition_audits(principal: ReadAudit, database: AdminDb, limit: Limit = 50, offset: Offset = 0):
    return await database.list_definition_audits(limit=limit, offset=offset)


@router.get("/audit/role-permissions", response_model=list[PermissionAuditResponse], tags=["identity audit"])
async def permission_audits(principal: ReadAudit, database: AdminDb, limit: Limit = 50, offset: Offset = 0):
    return await database.list_permission_audits(limit=limit, offset=offset)
