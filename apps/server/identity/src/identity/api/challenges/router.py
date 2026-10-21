from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from identity.api.dependencies import PrincipalDep, auth_rate_limit
from .dependencies import ChallengeServiceDep, RecentMfaDep
from .problems import ChallengeRoute, PROBLEM_RESPONSES
from .schemas import (
    AuthenticationChallengeResponse, ChallengeResponse, EmailOtpChallengeResponse, EmailOtpVerification, MfaStatus,
    RegistrationChallengeResponse, VerificationRequest, VerificationResponse,
)

CREATED = {201: {"headers": {"Location": {"description": "URI of the created challenge", "schema": {"type": "string", "format": "uri-reference"}}}}}
router = APIRouter(route_class=ChallengeRoute, dependencies=[Depends(auth_rate_limit)], responses=PROBLEM_RESPONSES)


def created(request: Request, response: Response, challenge: dict) -> dict:
    response.headers["Location"] = request.url_for("get_challenge", challenge_id=str(challenge["challenge_id"])).path
    return challenge


@router.post("/passkey-registration", response_model=RegistrationChallengeResponse, status_code=201,
    responses=CREATED, summary="Create a passkey enrollment challenge",
    description="Requires a passkey or email OTP challenge verified within five minutes in this session, including the first enrollment. Passkey user verification and a discoverable credential are required.")
async def create_registration(principal: RecentMfaDep, service: ChallengeServiceDep,
                              request: Request, response: Response):
    challenge = await service.create_registration(principal.user, principal.session.session_id)
    return created(request, response, challenge)


@router.post("/passkey-authentication", response_model=AuthenticationChallengeResponse, status_code=201,
    responses=CREATED, summary="Create a signed-in passkey MFA challenge")
async def create_authentication(principal: PrincipalDep, service: ChallengeServiceDep, request: Request, response: Response):
    challenge = await service.create_authentication(principal.user.user_id, principal.session.session_id)
    return created(request, response, challenge)


@router.post("/email-otp", response_model=EmailOtpChallengeResponse, status_code=201,
    responses=CREATED, summary="Create an email OTP challenge",
    description="Requests a six-digit code at the verified primary email. The code is never returned. Five attempts, five-minute expiry, and an account-wide 60-second resend interval apply.")
async def create_email_otp(principal: PrincipalDep, service: ChallengeServiceDep, request: Request, response: Response):
    challenge = await service.create_email_otp(principal.user.user_id, principal.session.session_id)
    return created(request, response, challenge)


@router.get("/mfa", response_model=MfaStatus, summary="Read recent MFA status for the current session")
async def mfa_status(principal: PrincipalDep, service: ChallengeServiceDep):
    return await service.mfa_status(principal.user.user_id, principal.session.session_id)


@router.get("/{challenge_id}", response_model=ChallengeResponse, name="get_challenge", summary="Read an owned challenge")
async def get_challenge(challenge_id: UUID, principal: PrincipalDep, service: ChallengeServiceDep):
    return await service.get(principal.user.user_id, principal.session.session_id, challenge_id)


@router.post("/{challenge_id}/verify", response_model=VerificationResponse, summary="Verify and complete a challenge once",
    description="Accepts an email code or the browser credential.toJSON() response. MFA verification is bound to the current session and lasts five minutes. Enrollment alone does not grant MFA status.")
async def verify_challenge(challenge_id: UUID, body: VerificationRequest, principal: PrincipalDep, service: ChallengeServiceDep):
    kwargs = {"code": body.code.get_secret_value()} if isinstance(body, EmailOtpVerification) else {
        "credential": body.credential.model_dump(mode="json", exclude_none=True),
    }
    return await service.verify(principal.user.user_id, principal.session.session_id, challenge_id, method=body.method, **kwargs)
