from http import HTTPStatus
import logging
from uuid import uuid4

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.exceptions import HTTPException

from auth_token.exceptions import AuthError
from identity.core.challenges import ChallengeError
from .schemas import ProblemDetails

logger = logging.getLogger(__name__)


def is_challenge_request(request: Request) -> bool:
    path = request.scope["path"].removeprefix(request.scope.get("root_path", ""))
    return path == "/api/challenges" or path.startswith("/api/challenges/")


def problem_response(status: int, detail: str, *, headers=None, errors=None) -> JSONResponse:
    problem = ProblemDetails(
        title="Unprocessable Content" if status == 422 else HTTPStatus(status).phrase,
        status=status, detail=detail, instance=f"urn:uuid:{uuid4()}", errors=errors,
    )
    return JSONResponse(status_code=status, content=problem.model_dump(mode="json", exclude_none=True),
        media_type="application/problem+json", headers={**(headers or {}), "Cache-Control": "no-store"})


PROBLEM_RESPONSES = {
    status: {"description": HTTPStatus(status).phrase,
             "content": {"application/problem+json": {"schema": ProblemDetails.model_json_schema()}},
             **({"headers": {"WWW-Authenticate": {"schema": {"type": "string"}}}} if status == 401 else {}),
             **({"headers": {"Retry-After": {"schema": {"type": "integer", "minimum": 0}}}} if status == 429 else {})}
    for status in (400, 401, 403, 404, 405, 409, 410, 415, 422, 429, 500, 503)
}

# Other identity routers retain their existing permission/account-policy errors.
RECENT_MFA_RESPONSES = {
    403: {
        "description": "Recent challenge verification is required, or access is forbidden by permissions or account policy.",
        "content": {
            **PROBLEM_RESPONSES[403]["content"],
            "application/json": {"schema": {
                "type": "object", "required": ["detail"], "properties": {"detail": {"type": "string"}},
            }},
        },
    },
}


class ChallengeRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request: Request):
            try:
                content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if request.method == "POST" and content_type and content_type != "application/json" and not content_type.endswith("+json"):
                    return problem_response(415, "Use application/json for challenge requests")
                response = await original(request)
                response.headers["Cache-Control"] = "no-store"
                return response
            except ChallengeError as exc:
                return problem_response(exc.status_code, exc.detail, headers=exc.headers)
            except AuthError as exc:
                return problem_response(exc.status_code, exc.detail,
                    headers={"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else {})
            except HTTPException as exc:
                return problem_response(exc.status_code, str(exc.detail), headers=exc.headers)
            except RequestValidationError as exc:
                errors = []
                for item in exc.errors():
                    location = list(item["loc"])
                    message = item["msg"]
                    if item["type"] in {"union_tag_invalid", "union_tag_not_found"}:
                        message = "Select a supported verification method"
                    elif item["type"] == "extra_forbidden":
                        location[-1] = "<unexpected field>"
                    errors.append({"type": item["type"], "location": location, "message": message})
                return problem_response(422, "Request validation failed", errors=errors)
            except IntegrityError:
                return problem_response(409, "The request conflicts with existing credentials")
            except SQLAlchemyError:
                return problem_response(503, "Challenge storage is temporarily unavailable")
            except Exception as exc:
                logger.error("Challenge processing failed (%s)", type(exc).__name__)
                return problem_response(500, "Challenge processing failed")

        return handler
