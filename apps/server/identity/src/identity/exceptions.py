from http import HTTPStatus

from auth_token.exceptions import AuthError


class AuthorizationError(AuthError):
    """An authenticated user lacks an identity-local permission."""

    status_code = HTTPStatus.FORBIDDEN
    error_code = "authorization_failed"
    default_detail = "Access denied"
