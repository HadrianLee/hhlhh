from fastapi import APIRouter, Depends, Request

from bff.api.dependencies import PrincipalDep, ServiceDep, auth_rate_limit
from bff.services.gateway import identity_path, relay

router = APIRouter()
JSON_BODY = {"requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}}}


@router.post("/auth/register", status_code=201, dependencies=[Depends(auth_rate_limit)], openapi_extra=JSON_BODY)
async def register(request: Request, service: ServiceDep):
    return await relay(request, service, "/api/auth/register")


@router.post("/auth/password/forgot", status_code=202, dependencies=[Depends(auth_rate_limit)], openapi_extra=JSON_BODY)
async def forgot_password(request: Request, service: ServiceDep):
    return await relay(request, service, "/api/auth/password/forgot")


@router.post("/auth/password/reset", status_code=204, dependencies=[Depends(auth_rate_limit)], openapi_extra=JSON_BODY)
async def reset_password(request: Request, service: ServiceDep):
    return await relay(request, service, "/api/auth/password/reset")


@router.post("/auth/email/verification/request", status_code=202, dependencies=[Depends(auth_rate_limit)], openapi_extra=JSON_BODY)
async def request_verification(request: Request, service: ServiceDep):
    return await relay(request, service, "/api/auth/email/verification/request")


@router.post("/auth/email/verification/confirm", status_code=204, dependencies=[Depends(auth_rate_limit)], openapi_extra=JSON_BODY)
async def confirm_verification(request: Request, service: ServiceDep):
    return await relay(request, service, "/api/auth/email/verification/confirm")


async def identity_api(path: str, request: Request, principal: PrincipalDep, service: ServiceDep):
    return await relay(request, service, identity_path(path, request.method), principal=principal)


for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
    router.add_api_route("/identity/{path:path}", identity_api, methods=[method],
        operation_id=f"identity_api_{method.lower()}",
        summary="Call an allowlisted identity endpoint using the browser session",
        description="Path corresponds to identity's /api/{path}. Supports account, challenge, and identity-local administration routes. Identity enforces permissions and recent MFA. Login, refresh, and session administration are handled by BFF's /api/auth routes.",
        openapi_extra={"requestBody": {**JSON_BODY["requestBody"], "required": False}} if method != "GET" else None)
