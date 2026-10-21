from http import HTTPStatus


class AuthError(Exception):
    """Base exception for authentication failures."""

    status_code: int = HTTPStatus.UNAUTHORIZED
    error_code: str = "authentication_failed"
    default_detail: str = "Authentication failed"

    def __init__(self, detail: str | None = None) -> None:
        self.detail = detail or self.default_detail

        super().__init__(self.detail)

    def to_dict(self) -> dict[str, str]:
        return {
            "error": self.error_code,
            "detail": self.detail,
        }


class AuthenticationError(AuthError):
    """Base exception for failures to authenticate a user."""

    status_code = HTTPStatus.UNAUTHORIZED
    error_code = "authentication_failed"
    default_detail = "Authentication failed"


class MissingTokenError(AuthenticationError):
    error_code = "missing_token"
    default_detail = "Access token is required"


class TokenExpiredError(AuthenticationError):
    error_code = "token_expired"
    default_detail = "Access token has expired"


class InvalidTokenError(AuthenticationError):
    error_code = "invalid_token"
    default_detail = "Access token is invalid"
