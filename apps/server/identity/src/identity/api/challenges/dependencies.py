from typing import Annotated

from fastapi import Depends, Request

from identity.api.dependencies import Principal, PrincipalDep, require_permission
from identity.core.challenges import ChallengeError
from identity.db.services.challenge import ChallengeDbService
from identity.permissions import Permission


def get_challenge_service(request: Request) -> ChallengeDbService:
    return ChallengeDbService(
        request.app.state.identity_db.db, request.app.state.identity_security,
        request.app.state.identity_email_delivery,
    )


ChallengeServiceDep = Annotated[ChallengeDbService, Depends(get_challenge_service)]


async def require_recent_mfa(principal: PrincipalDep, service: ChallengeServiceDep) -> Principal:
    status = await service.mfa_status(principal.user.user_id, principal.session.session_id)
    if status["verified_at"] is None:
        raise ChallengeError(403, "Complete a recent MFA challenge for this session")
    return principal


RecentMfaDep = Annotated[Principal, Depends(require_recent_mfa)]


def require_permission_with_mfa(action: Permission):
    async def dependency(
        principal: Annotated[Principal, Depends(require_permission(action))],
        service: ChallengeServiceDep,
    ) -> Principal:
        return await require_recent_mfa(principal, service)
    return dependency
