from http import HTTPStatus
import logging
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException

from bff.api.auth.schemas import ProblemDetails
from bff.core.security import CSRF_COOKIE, SESSION_COOKIE
from bff.exceptions import BffError

logger = logging.getLogger(__name__)


def clear_cookies(response) -> None:
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/", secure=True, httponly=True, samesite="lax")


def problem_response(status: int, detail: str, *, headers=None) -> JSONResponse:
    body = ProblemDetails(title="Unprocessable Content" if status == 422 else HTTPStatus(status).phrase,
                          status=status, detail=detail, instance=f"urn:uuid:{uuid4()}")
    return JSONResponse(body.model_dump(), status_code=status, media_type="application/problem+json",
                        headers={**(headers or {}), "Cache-Control": "no-store"})


PROBLEM_RESPONSES = {
    status: {"description": HTTPStatus(status).phrase, "content": {
        "application/problem+json": {"schema": ProblemDetails.model_json_schema()},
    }} for status in (400, 401, 403, 404, 405, 409, 413, 415, 422, 429, 500, 502, 503, 504)
}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(BffError)
    async def bff_error(request: Request, exc: BffError):
        response = problem_response(exc.status_code, exc.detail, headers=exc.headers)
        if exc.clear_session:
            clear_cookies(response)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return problem_response(422, "Request validation failed")

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return problem_response(exc.status_code, str(exc.detail), headers=exc.headers)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError):
        logger.error("BFF database operation failed (%s)", type(exc).__name__)
        return problem_response(503, "Session storage is unavailable")

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        logger.error("BFF request failed (%s)", type(exc).__name__)
        return problem_response(500, "Request processing failed")
