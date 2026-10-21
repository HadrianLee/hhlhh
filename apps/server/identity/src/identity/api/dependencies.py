from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import time
from typing import Annotated, Any
from uuid import UUID

from fastapi import Depends, HTTPException, Request
from auth_token.dependencies import verify_jwt
from auth_token.exceptions import InvalidTokenError
from identity.db.models.identity import User, UserSession
from identity.db.services.identity import IdentityDbService
from identity.exceptions import AuthorizationError
from identity.permissions import Permission
from identity.services.identity import IdentityService


def get_database(request: Request) -> IdentityDbService:
    return request.app.state.identity_db


def get_service(request: Request) -> IdentityService:
    return IdentityService(
        get_database(request), request.app.state.key_manager, request.app.state.identity_security,
        request.app.state.identity_email_delivery,
    )


@dataclass(frozen=True)
class Principal:
    user: User
    session: UserSession


async def current_principal(
    payload: Annotated[dict[str, Any], Depends(verify_jwt)],
    database: Annotated[IdentityDbService, Depends(get_database)],
) -> Principal:
    try:
        user_id, session_id = UUID(payload["sub"]), UUID(payload["sid"])
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise InvalidTokenError() from exc
    row = await database.get_authenticated_user(user_id, session_id)
    if row is None:
        raise InvalidTokenError("session is no longer active")
    return Principal(user=row[0], session=row[1])


def require_permission(action: Permission):
    async def dependency(
        principal: Annotated[Principal, Depends(current_principal)],
        database: Annotated[IdentityDbService, Depends(get_database)],
    ) -> Principal:
        if not await database.has_permission(user_id=principal.user.user_id, action=action):
            raise AuthorizationError("identity permission required")
        return principal
    return dependency


class AuthRateLimiter:
    """Bounded per-process limit; deployments can add a shared limit at their proxy."""

    def __init__(self) -> None:
        self._windows: OrderedDict[str, tuple[float, int]] = OrderedDict()

    def check(self, key: str) -> None:
        now = time.monotonic()
        started, count = self._windows.pop(key, (now, 0))
        if now - started >= 60:
            started, count = now, 0
        self._windows[key] = (started, count + 1)
        if len(self._windows) > 10000:
            self._windows.popitem(last=False)
        if count >= 30:
            raise HTTPException(status_code=429, detail="too many authentication requests", headers={"Retry-After": "60"})


async def auth_rate_limit(request: Request) -> None:
    key = request.client.host if request.client else "unknown"
    request.app.state.identity_rate_limiter.check(key)


DatabaseDep = Annotated[IdentityDbService, Depends(get_database)]
ServiceDep = Annotated[IdentityService, Depends(get_service)]
PrincipalDep = Annotated[Principal, Depends(current_principal)]
