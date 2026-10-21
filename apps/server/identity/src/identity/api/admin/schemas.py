from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from identity.api.auth.schemas import InputModel, UserResponse


class AdminUserResponse(UserResponse):
    is_banned: bool


class BanRequest(InputModel):
    is_banned: StrictBool


class RoleCreateRequest(InputModel):
    name: str = Field(min_length=1, max_length=100, pattern=r"^\S(?:.*\S)?$")
    description: str = Field(default="", max_length=10000)


class PatchModel(InputModel):
    @model_validator(mode="after")
    def validate_changes(self):
        if not self.model_fields_set or any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("provide at least one non-null field")
        return self


class RoleUpdateRequest(PatchModel):
    name: str | None = Field(default=None, min_length=1, max_length=100, pattern=r"^\S(?:.*\S)?$")
    description: str | None = Field(default=None, max_length=10000)


class RoleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    role_id: UUID
    name: str
    description: str
    is_system: bool


class PermissionCreateRequest(InputModel):
    action: str = Field(min_length=1, max_length=160, pattern=r"^[a-z][a-z0-9_.:-]*$")
    description: str = Field(default="", max_length=10000)


class PermissionUpdateRequest(PatchModel):
    action: str | None = Field(default=None, min_length=1, max_length=160, pattern=r"^[a-z][a-z0-9_.:-]*$")
    description: str | None = Field(default=None, max_length=10000)


class PermissionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    permission_id: UUID
    action: str
    description: str


class ChangedResponse(BaseModel):
    changed: bool


class AuditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    created_at: datetime
    actor_user_id: UUID
    action_type: str
    role_id: UUID | None
    role_name_snapshot: str
    changes: dict[str, Any]


class RoleAuditResponse(AuditResponse):
    role_audit_id: UUID
    target_user_id: UUID


class DefinitionAuditResponse(AuditResponse):
    role_definition_audit_id: UUID


class PermissionAuditResponse(AuditResponse):
    role_permission_audit_id: UUID
    permission_id: UUID | None
    permission_action_snapshot: str
