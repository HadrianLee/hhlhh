from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Response

from identity.api.auth.schemas import (
    EmailRequest, LoginRequest, LoginResponse, MessageResponse, PasswordChangeRequest,
    PasswordResetRequest, RefreshRequest, RegisterRequest, SessionResponse, TokenRequest, UserResponse,
)
from identity.api.dependencies import (
    DatabaseDep, PrincipalDep, ServiceDep, auth_rate_limit,
)
from identity.db.errors import IdentityNotFoundError
from identity.api.challenges.dependencies import RecentMfaDep
from identity.api.challenges.problems import RECENT_MFA_RESPONSES
from identity.api.auth.passkey_schemas import PasskeyLoginRequest, PasskeyOptionsRequest, PasskeyOptionsResponse

router = APIRouter(dependencies=[Depends(auth_rate_limit)])


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(request: RegisterRequest, service: ServiceDep, background: BackgroundTasks):
    user = await service.register(email=str(request.email), username=request.username, password=request.password.get_secret_value())
    background.add_task(service.request_verification, user.email)
    return user


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, service: ServiceDep, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return await service.login(email=str(request.email), password=request.password.get_secret_value())


@router.post("/passkey/options", response_model=PasskeyOptionsResponse, status_code=201,
    description="Create a five-minute discoverable passkey sign-in challenge. browser_binding is supplied by BFF, derived from its HttpOnly browser cookie.")
async def passkey_options(request: PasskeyOptionsRequest, service: ServiceDep, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return await service.passkey_options(request.browser_binding.get_secret_value())


@router.post("/passkey/login", response_model=LoginResponse,
    description="Verify a browser-bound, single-use discoverable passkey assertion and create an identity session. User verification is required.")
async def passkey_login(request: PasskeyLoginRequest, service: ServiceDep, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return await service.login_passkey(challenge_id=request.challenge_id,
        browser_binding=request.browser_binding.get_secret_value(),
        credential=request.credential.model_dump(mode="json", exclude_none=True))


@router.post("/refresh", response_model=LoginResponse)
async def refresh(request: RefreshRequest, service: ServiceDep, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return await service.refresh(request.refresh_token.get_secret_value())


@router.post("/logout", status_code=204)
async def logout(principal: PrincipalDep, database: DatabaseDep) -> Response:
    await database.revoke_session(principal.session.session_id)
    return Response(status_code=204)


@router.post("/logout-all", status_code=204)
async def logout_all(principal: PrincipalDep, database: DatabaseDep) -> Response:
    await database.revoke_all_user_sessions(principal.user.user_id)
    return Response(status_code=204)


@router.get("/sessions", response_model=list[SessionResponse])
async def sessions(
    principal: PrincipalDep, database: DatabaseDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return await database.list_sessions(principal.user.user_id, limit=limit, offset=offset)


@router.delete("/sessions/{session_id}", status_code=204)
async def revoke_session(session_id: UUID, principal: PrincipalDep, database: DatabaseDep) -> Response:
    session = await database.get_session(session_id)
    if session is None or session.user_id != principal.user.user_id:
        raise IdentityNotFoundError("session not found")
    await database.revoke_session(session_id)
    return Response(status_code=204)


@router.post("/password/change", status_code=204, responses=RECENT_MFA_RESPONSES,
    description="Requires a passkey or email OTP challenge verified within five minutes in this session. Revokes all sessions after changing the password.")
async def change_password(request: PasswordChangeRequest, principal: RecentMfaDep, service: ServiceDep) -> Response:
    await service.change_password(principal.user, principal.session.session_id, request.new_password.get_secret_value())
    return Response(status_code=204)


@router.post("/password/forgot", response_model=MessageResponse, status_code=202)
async def forgot_password(request: EmailRequest, service: ServiceDep, background: BackgroundTasks):
    background.add_task(service.request_password_reset, str(request.email))
    return {"message": "If this account exists, password reset instructions will be delivered."}


@router.post("/password/reset", status_code=204)
async def reset_password(request: PasswordResetRequest, service: ServiceDep) -> Response:
    await service.reset_password(request.token.get_secret_value(), request.new_password.get_secret_value())
    return Response(status_code=204)


@router.post("/email/verification/request", response_model=MessageResponse, status_code=202)
async def request_verification(request: EmailRequest, service: ServiceDep, background: BackgroundTasks):
    background.add_task(service.request_verification, str(request.email))
    return {"message": "If verification is needed, instructions will be delivered."}


@router.post("/email/verification/confirm", status_code=204)
async def confirm_verification(request: TokenRequest, service: ServiceDep) -> Response:
    await service.confirm_email(request.token.get_secret_value())
    return Response(status_code=204)
