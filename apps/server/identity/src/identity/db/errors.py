class IdentityDbError(Exception):
    """Base exception for identity persistence operations."""


class IdentityNotFoundError(IdentityDbError):
    pass


class IdentityConflictError(IdentityDbError):
    pass


class IdentityPolicyError(IdentityDbError):
    pass
