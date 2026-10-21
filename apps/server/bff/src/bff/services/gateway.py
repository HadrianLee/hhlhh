import re

from fastapi import Request, Response

from bff.exception_handlers import clear_cookies
from bff.exceptions import BffError, SessionInvalidError
from bff.services.session import Principal, SessionService

UUID_PATH = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
IDENTITY_ROUTES = (
    (r"users/me", {"GET", "PATCH"}),
    (r"users/me/permissions", {"GET"}),
    (r"users/me/emails", {"GET", "POST"}),
    (rf"users/me/emails/{UUID_PATH}", {"DELETE"}),
    (rf"users/me/emails/{UUID_PATH}/(?:verification|primary)", {"POST"}),
    (r"auth/password/change", {"POST"}),
    (r"challenges/(?:passkey-registration|passkey-authentication|email-otp)", {"POST"}),
    (r"challenges/mfa", {"GET"}),
    (rf"challenges/{UUID_PATH}", {"GET"}),
    (rf"challenges/{UUID_PATH}/verify", {"POST"}),
    (r"users", {"GET"}),
    (rf"users/{UUID_PATH}", {"GET"}),
    (rf"users/{UUID_PATH}/ban", {"PATCH"}),
    (rf"users/{UUID_PATH}/sessions", {"GET", "DELETE"}),
    (rf"users/{UUID_PATH}/(?:roles|permissions)", {"GET"}),
    (rf"users/{UUID_PATH}/roles/{UUID_PATH}", {"PUT", "DELETE"}),
    (r"roles", {"GET", "POST"}),
    (rf"roles/{UUID_PATH}", {"GET", "PATCH", "DELETE"}),
    (rf"roles/{UUID_PATH}/permissions", {"GET"}),
    (rf"roles/{UUID_PATH}/permissions/{UUID_PATH}", {"PUT", "DELETE"}),
    (r"permissions", {"GET", "POST"}),
    (rf"permissions/{UUID_PATH}", {"GET", "PATCH", "DELETE"}),
    (r"audit/(?:role-assignments|role-definitions|role-permissions)", {"GET"}),
)
def safe_path(path: str) -> None:
    if (not path or path.startswith("/") or any(char in path for char in "\\%?#")
            or any(part in {"", ".", ".."} for part in path.split("/"))):
        raise BffError(404, "API path not found")


def identity_path(path: str, method: str) -> str:
    safe_path(path)
    for pattern, methods in IDENTITY_ROUTES:
        if re.fullmatch(pattern, path):
            if method not in methods:
                raise BffError(405, "Method not allowed", headers={"Allow": ", ".join(sorted(methods))})
            return "/api/" + path
    raise BffError(404, "Identity API path not found")


async def relay(request: Request, service: SessionService, path: str, *, principal: Principal | None = None,
                upstream: str | None = None) -> Response:
    response = await service.identity.request(request.method, path,
        access_token=principal.access_token if principal else None,
        body=await request.body(), query=request.scope["query_string"], upstream=upstream)
    if response.status_code == 401 and principal is not None and upstream is None:
        async with service.database.locked(session_id=principal.session.session_id) as (database, row):
            if row is not None:
                service.database.revoke(database, row, "identity_rejected", pending=False)
        raise SessionInvalidError()
    service.identity.require_success(response)
    headers = {}
    media_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
    if response.content and media_type not in {"application/json", "application/problem+json"}:
        raise BffError(502, "Upstream returned an unsupported response type")
    if media_type:
        headers["Content-Type"] = media_type
    location = response.headers.get("location", "")
    if upstream is None and location.startswith("/api/challenges/"):
        headers["Location"] = "/api/identity/" + location.removeprefix("/api/")
    result = Response(content=response.content if request.method != "HEAD" else b"",
                      status_code=response.status_code, headers=headers)
    if principal is not None and upstream is None and request.method == "POST" and (
        path == "/api/auth/password/change" or re.fullmatch(rf"/api/users/me/emails/{UUID_PATH}/primary", path)
    ):
        await service.database.revoke_user(principal.session.user_id, reason="credentials_changed", pending=False)
        clear_cookies(result)
    return result
