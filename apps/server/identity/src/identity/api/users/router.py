from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Response

from identity.api.auth.schemas import (
    EmailRequest, MessageResponse, SecondaryEmailResponse, UserResponse, UserUpdateRequest,
)
from identity.api.dependencies import (
    DatabaseDep, PrincipalDep, ServiceDep, auth_rate_limit,
)
from identity.db.errors import IdentityNotFoundError
from identity.api.challenges.dependencies import RecentMfaDep
from identity.api.challenges.problems import RECENT_MFA_RESPONSES

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def me(principal: PrincipalDep):
    return principal.user


@router.patch("/me", response_model=UserResponse)
async def update_me(request: UserUpdateRequest, principal: PrincipalDep, database: DatabaseDep):
    return await database.update_username(principal.user.user_id, request.username)


@router.get("/me/permissions", response_model=list[str])
async def my_identity_permissions(principal: PrincipalDep, database: DatabaseDep, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return sorted(await database.list_user_permissions(principal.user.user_id))


@router.get("/me/emails", response_model=list[SecondaryEmailResponse])
async def emails(principal: PrincipalDep, database: DatabaseDep):
    return await database.list_secondary_emails(principal.user.user_id)


@router.post("/me/emails", response_model=SecondaryEmailResponse, status_code=201, dependencies=[Depends(auth_rate_limit)],
    responses=RECENT_MFA_RESPONSES, description="Requires recent challenge verification in the current session.")
async def add_email(request: EmailRequest, principal: RecentMfaDep, database: DatabaseDep):
    return await database.add_secondary_email(principal.user.user_id, str(request.email), session_id=principal.session.session_id)


@router.post(
    "/me/emails/{email_id}/verification", response_model=MessageResponse,
    status_code=202, dependencies=[Depends(auth_rate_limit)],
)
async def verify_email(email_id: UUID, principal: PrincipalDep, service: ServiceDep, background: BackgroundTasks):
    emails = await service.db.list_secondary_emails(principal.user.user_id)
    if not any(row.secondary_email_id == email_id for row in emails):
        raise IdentityNotFoundError("email not found")
    background.add_task(service.request_secondary_verification, principal.user, email_id)
    return {"message": "If verification is needed, instructions will be delivered."}


@router.delete("/me/emails/{email_id}", status_code=204, responses=RECENT_MFA_RESPONSES,
    description="Requires recent challenge verification in the current session.")
async def delete_email(email_id: UUID, principal: RecentMfaDep, database: DatabaseDep) -> Response:
    if not await database.delete_secondary_email(principal.user.user_id, email_id, session_id=principal.session.session_id):
        raise IdentityNotFoundError("email not found")
    return Response(status_code=204)


@router.post("/me/emails/{email_id}/primary", response_model=UserResponse, dependencies=[Depends(auth_rate_limit)],
    responses=RECENT_MFA_RESPONSES,
    description="Requires recent challenge verification in the current session and an owned, verified secondary email. Revokes all sessions after the change.")
async def promote_email(email_id: UUID, principal: RecentMfaDep, service: ServiceDep):
    return await service.promote_secondary_email(principal.user, principal.session.session_id, email_id)
