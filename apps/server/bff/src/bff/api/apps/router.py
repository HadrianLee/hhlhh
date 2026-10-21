from fastapi import APIRouter, Depends, Request

from bff.api.dependencies import PrincipalDep, ServiceDep, csrf_protection
from bff.exceptions import BffError
from bff.services.gateway import relay, safe_path

router = APIRouter(dependencies=[Depends(csrf_protection)])


async def application_api(service_name: str, path: str, request: Request, principal: PrincipalDep, service: ServiceDep):
    safe_path(path)
    upstream = service.security.settings.upstreams.get(service_name)
    if upstream is None:
        raise BffError(404, "Application service not found")
    return await relay(request, service, "/" + path, principal=principal, upstream=upstream)


for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
    router.add_api_route("/{service_name}/{path:path}", application_api, methods=[method],
        operation_id=f"application_api_{method.lower()}", summary="Call a configured application API",
        description="BFF_UPSTREAMS maps service names to fixed internal origins. The downstream application verifies the JWT and enforces its own permissions. Bodies and responses are bounded JSON; files, streaming, and WebSockets need separate routes.",
        openapi_extra={"requestBody": {"required": False, "content": {"application/json": {"schema": {"type": "object"}}}}} if method != "GET" else None)
