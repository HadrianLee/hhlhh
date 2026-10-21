from collections import OrderedDict
import hmac
import re
import time
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import APIKeyCookie

from bff.core.security import CSRF_COOKIE, SESSION_COOKIE
from bff.exceptions import BffError
from bff.services.session import Principal, SessionService

cookie_security = APIKeyCookie(name=SESSION_COOKIE, auto_error=False)


def get_service(request: Request) -> SessionService:
    return request.app.state.session_service


ServiceDep = Annotated[SessionService, Depends(get_service)]


async def current_principal(cookie: Annotated[str | None, Depends(cookie_security)], service: ServiceDep) -> Principal:
    return await service.authenticate(cookie)


PrincipalDep = Annotated[Principal, Depends(current_principal)]


async def csrf_protection(request: Request) -> None:
    security = request.app.state.security
    unsafe = request.method not in {"GET", "HEAD", "OPTIONS"}
    csrf_endpoint = request.scope["path"].removeprefix(request.scope.get("root_path", "")) == "/api/auth/csrf"
    if unsafe or csrf_endpoint:
        origins = request.headers.getlist("origin")
        if ((unsafe and origins != [security.settings.public_origin]) or
                (origins and origins != [security.settings.public_origin]) or
                request.headers.get("sec-fetch-site") not in {None, "same-origin", "none"}):
            raise BffError(403, "Use the configured frontend origin")
    if not unsafe:
        return
    session_cookie = request.cookies.get(SESSION_COOKIE)
    authenticated = security.valid_secret(session_cookie)
    # CSRF proves possession of the matching browser token. Protected endpoints
    # separately authenticate the session through PrincipalDep.
    secret = session_cookie if authenticated else request.cookies.get(CSRF_COOKIE)
    tokens = request.headers.getlist("x-csrf-token")
    if (not security.valid_secret(secret) or len(tokens) != 1 or re.fullmatch(r"[0-9a-f]{64}", tokens[0]) is None
            or not hmac.compare_digest(security.csrf_token(secret, authenticated=authenticated), tokens[0])):
        raise BffError(403, "A valid X-CSRF-Token header is required")


class AuthRateLimiter:
    """Bounded per-worker login limit; configure a shared limit at the edge too."""

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
            raise BffError(429, "Too many authentication requests", headers={"Retry-After": "60"})


async def auth_rate_limit(request: Request) -> None:
    request.app.state.auth_rate_limiter.check(request.client.host if request.client else "unknown")
