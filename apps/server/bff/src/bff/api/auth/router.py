from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import select

from bff.api.auth.schemas import CsrfResponse, EventResponse, LoginRequest, LoginResponse, PasskeyLoginRequest, SessionResponse
from bff.core.identity import PasskeyOptionsResponse
from bff.api.dependencies import PrincipalDep, ServiceDep, auth_rate_limit
from bff.core.security import CSRF_COOKIE, SESSION_COOKIE
from bff.db.models.session import BrowserSession, SessionEvent
from bff.db.services.session import aware, utcnow
from bff.exception_handlers import clear_cookies
from bff.exceptions import BffError, SessionInvalidError

router = APIRouter()


@router.get("/csrf", response_model=CsrfResponse,
            description="Fetch before login and after a session change. Send csrf_token as X-CSRF-Token on every write, with an Origin header matching BFF_PUBLIC_ORIGIN.")
async def csrf(request: Request, response: Response, service: ServiceDep):
    security = request.app.state.security
    cookie = request.cookies.get(SESSION_COOKIE)
    authenticated = False
    if cookie is not None:
        try:
            await service.authenticate(cookie)
        except SessionInvalidError:
            response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        else:
            authenticated = True
    if not authenticated:
        cookie = request.cookies.get(CSRF_COOKIE)
        if not security.valid_secret(cookie):
            cookie = security.new_secret()
        response.set_cookie(CSRF_COOKIE, cookie, max_age=3600, path="/", secure=True, httponly=True, samesite="lax")
    return {"csrf_token": security.csrf_token(cookie, authenticated=authenticated)}


@router.post("/login", response_model=LoginResponse, dependencies=[Depends(auth_rate_limit)])
async def login(body: LoginRequest, request: Request, response: Response, service: ServiceDep):
    row, cookie = await service.login(email=str(body.email), password=body.password.get_secret_value(),
        previous_cookie=request.cookies.get(SESSION_COOKIE),
        ip_address=request.client.host[:45] if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:512] or None)
    return complete_login(row, cookie, response, service)


def complete_login(row, cookie: str, response: Response, service):
    response.set_cookie(SESSION_COOKIE, cookie, max_age=max(1, int((aware(row.expires_at) - utcnow()).total_seconds())),
                        path="/", secure=True, httponly=True, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return LoginResponse(csrf_token=service.security.csrf_token(cookie, authenticated=True))


def passkey_binding(request: Request, service) -> str:
    cookie = request.cookies.get(SESSION_COOKIE)
    if not service.security.valid_secret(cookie):
        cookie = request.cookies.get(CSRF_COOKIE)
    if not service.security.valid_secret(cookie):
        raise BffError(403, "Fetch a CSRF token before signing in")
    return service.security.passkey_login_binding(cookie)


@router.post("/passkey/options", response_model=PasskeyOptionsResponse, status_code=201,
             dependencies=[Depends(auth_rate_limit)])
async def passkey_options(request: Request, service: ServiceDep):
    return await service.identity.passkey_options(passkey_binding(request, service))


@router.post("/passkey/login", response_model=LoginResponse, dependencies=[Depends(auth_rate_limit)])
async def passkey_login(body: PasskeyLoginRequest, request: Request, response: Response, service: ServiceDep):
    row, cookie = await service.login_passkey(challenge_id=body.challenge_id,
        credential=body.credential.model_dump(mode="json", exclude_none=True),
        browser_binding=passkey_binding(request, service), previous_cookie=request.cookies.get(SESSION_COOKIE),
        ip_address=request.client.host[:45] if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:512] or None)
    return complete_login(row, cookie, response, service)


@router.get("/session", response_model=SessionResponse)
async def current_session(principal: PrincipalDep):
    return SessionResponse.from_session(principal.session, principal.session.session_id)


@router.get("/sessions", response_model=list[SessionResponse])
async def sessions(principal: PrincipalDep, service: ServiceDep,
                   limit: Annotated[int, Query(ge=1, le=100)] = 50,
                   offset: Annotated[int, Query(ge=0)] = 0):
    rows = await service.database.list(principal.session.user_id, limit=limit, offset=offset)
    return [SessionResponse.from_session(row, principal.session.session_id) for row in rows]


@router.get("/sessions/{session_id}/events", response_model=list[EventResponse])
async def session_events(session_id: UUID, principal: PrincipalDep, service: ServiceDep,
                         limit: Annotated[int, Query(ge=1, le=100)] = 50,
                         offset: Annotated[int, Query(ge=0)] = 0):
    async with service.database.db.session() as database:
        owned = await database.scalar(select(BrowserSession.session_id).where(
            BrowserSession.session_id == session_id, BrowserSession.user_id == principal.session.user_id))
        if owned is None:
            raise BffError(404, "Session not found")
        return list(await database.scalars(select(SessionEvent).where(SessionEvent.session_id == session_id)
            .order_by(SessionEvent.created_at.desc(), SessionEvent.event_id).limit(limit).offset(offset)))


@router.delete("/sessions/{session_id}", status_code=204)
async def revoke_session(session_id: UUID, principal: PrincipalDep, service: ServiceDep):
    await service.revoke_session(principal, session_id)
    response = Response(status_code=204)
    if session_id == principal.session.session_id:
        clear_cookies(response)
    return response


@router.post("/logout", status_code=204)
async def logout(request: Request, service: ServiceDep):
    # Local logout remains available even while identity is unavailable.
    await service.logout(request.cookies.get(SESSION_COOKIE))
    response = Response(status_code=204)
    clear_cookies(response)
    return response


@router.post("/logout-all", status_code=204)
async def logout_all(principal: PrincipalDep, service: ServiceDep):
    await service.logout_all(principal)
    response = Response(status_code=204)
    clear_cookies(response)
    return response
