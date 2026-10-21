from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException
from sqlalchemy.exc import IntegrityError, OperationalError, TimeoutError as DatabaseTimeoutError

from auth_token.exceptions import AuthError
from identity.db.errors import IdentityConflictError, IdentityNotFoundError, IdentityPolicyError
from identity.services.identity import IdentityUnavailableError
from identity.api.challenges.problems import is_challenge_request, problem_response
from identity.core.challenges import ChallengeError

def register_auth_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ChallengeError)
    async def handle_challenge(request: Request, exc: ChallengeError):
        return problem_response(exc.status_code, exc.detail, headers=exc.headers)

    @app.exception_handler(HTTPException)
    async def handle_http(request: Request, exc: HTTPException):
        if is_challenge_request(request):
            return problem_response(exc.status_code, str(exc.detail), headers=exc.headers)
        return await http_exception_handler(request, exc)

    @app.exception_handler(IdentityUnavailableError)
    @app.exception_handler(OperationalError)
    @app.exception_handler(DatabaseTimeoutError)
    async def handle_unavailable(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": "identity service is temporarily unavailable"})

    @app.exception_handler(IntegrityError)
    async def handle_integrity(request: Request, exc: IntegrityError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": "request conflicts with current data"})

    @app.exception_handler(RequestValidationError)
    async def handle_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{"type": error["type"], "loc": list(error["loc"]), "msg": error["msg"]}
                  for error in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(IdentityConflictError)
    async def handle_conflict(request: Request, exc: IdentityConflictError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(IdentityNotFoundError)
    async def handle_not_found(request: Request, exc: IdentityNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(IdentityPolicyError)
    async def handle_policy(request: Request, exc: IdentityPolicyError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(AuthError)
    async def handle_auth_error(
        request: Request,
        exc: AuthError,
    ) -> JSONResponse:
        headers: dict[str, str] = {}

        if exc.status_code == 401:
            headers["WWW-Authenticate"] = "Bearer"

        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_dict(),
            headers=headers,
        )
