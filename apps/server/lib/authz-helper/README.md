# Authorization model helpers

`authz-helper` shares SQLAlchemy columns for roles, permissions, assignments, and
audit records. Each application supplies its own concrete tables, foreign keys,
permission names, and database queries.

This separates two questions: Identity authenticates **who** made a request; the
application decides **what** that user can do with its data. Reusing columns does
not require every application to share a database or permission service.

## Available mixins

| Mixin | Columns or behavior |
| --- | --- |
| `CreatedAtMixin` | Server-generated creation timestamp |
| `TimestampMixin` | Creation and update timestamps |
| `RoleMixin` | UUID, unique name, description, and protected-system-role flag |
| `PermissionMixin` | UUID, unique action string, and description |
| `RolePermissionMixin` | Composite role/permission link with cascading foreign keys |
| `UserRoleMixin` | Composite user/role assignment, assigning user, and timestamp |
| `RoleAuditLogMixin` | User-role assignment/removal with a role-name snapshot |
| `RoleDefinitionAuditLogMixin` | Role creation/update/deletion with snapshots and changes |
| `RolePermissionAuditLogMixin` | Permission attachment/removal with role/permission snapshots |

Audit action enums define the accepted actions, and the audit mixins contribute
database check constraints. `changes` uses JSONB on PostgreSQL and JSON on other
supported SQLAlchemy databases. These models do not write audit records
automatically; the application's transaction must insert them.

## Define application tables

For example, an application can choose its own table names and foreign-key
targets while reusing the column definitions:

```python
from sqlalchemy.orm import DeclarativeBase

from authz_helper.mixins import (
    PermissionMixin,
    RoleMixin,
    RolePermissionMixin,
    TimestampMixin,
)


class Base(DeclarativeBase):
    pass


class Role(TimestampMixin, RoleMixin, Base):
    __tablename__ = "app_roles"


class Permission(TimestampMixin, PermissionMixin, Base):
    __tablename__ = "app_permissions"


class RolePermission(RolePermissionMixin, Base):
    __tablename__ = "app_role_permissions"
    __role_fk_target__ = "app_roles.role_id"
    __permission_fk_target__ = "app_permissions.permission_id"
```

For tables in a named schema, use schema-qualified targets such as
`my_app.app_roles.role_id`. User assignments and audit mixins additionally need
the applicable `__user_fk_target__`, `__role_fk_target__`, and
`__permission_fk_target__` values. Keep the mixin's contributed constraints when
adding application-specific table arguments. See Identity's concrete models in
[`identity/db/models/identity.py`](../../identity/src/identity/db/models/identity.py)
for the existing usage.

The database service still owns permission lookup, system-role protection,
assignment changes, and audit insertion. Those rules are not enforced merely by
inheriting a mixin.

## Permission values

The optional `permission_types.Permission` base is an empty string enum for an
application to extend. `permission_values()` accepts members of that enum family
and returns their unique values as a `frozenset[str]`; other inputs raise
`TypeError`. Applications can also define their own permission enum and conversion
contract, as Identity does.

## Workspace usage

Install the locked packages from the repository root:

```bash
uv sync --frozen --directory apps/server --all-packages
```

Add `authz-helper` as a workspace dependency where needed. There is no standalone
HTTP service or package-specific test suite; Identity's API tests exercise its
concrete role/permission models and local authorization behavior. See the
[server test commands](../../README.md#checks).
