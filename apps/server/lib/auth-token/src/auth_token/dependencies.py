from json import JSONDecodeError
from typing import Annotated, Any

import os
import ssl
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth_token.exceptions import InvalidTokenError, MissingTokenError, TokenExpiredError

ISSUER = os.environ["JWT_ISSUER"]
AUDIENCE = os.environ["JWT_AUDIENCE"]
JWKS_URL = os.environ["JWKS_URL"]
JWT_CLOCK_SKEW_SECONDS = int(os.environ.get("JWT_CLOCK_SKEW_SECONDS", "5"))

if not ISSUER.strip() or not AUDIENCE.strip():
    raise ValueError("JWT_ISSUER and JWT_AUDIENCE must not be blank")
if JWT_CLOCK_SKEW_SECONDS < 0:
    raise ValueError("JWT_CLOCK_SKEW_SECONDS must be nonnegative")

security = HTTPBearer(auto_error=False)
jwks_client = jwt.PyJWKClient(
    JWKS_URL, timeout=5, cache_jwk_set=True, lifespan=300, cache_keys=False,
    ssl_context=ssl.create_default_context(),
)


def decode_jwt(token: str) -> dict[str, Any]:
    """Verify an RS256 access token using only the configured public JWKS."""
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if (header.get("alg") != "RS256" or header.get("typ") != "JWT"
                or not isinstance(kid, str) or not kid.strip() or "crit" in header):
            raise jwt.InvalidTokenError("invalid JWT header")
        signing_key = jwks_client.get_signing_key(kid)
        if signing_key.key_type != "RSA" or signing_key.algorithm_name != "RS256":
            raise jwt.InvalidTokenError("unexpected signing key type")
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            leeway=JWT_CLOCK_SKEW_SECONDS,
            options={"require": ["iss", "aud", "sub", "exp", "iat", "nbf", "jti"]},
        )
        if not payload["sub"].strip() or not payload["jti"].strip():
            raise jwt.InvalidTokenError("empty identity claim")
        if any(type(payload[name]) not in (int, float) for name in ("exp", "iat", "nbf")):
            raise jwt.InvalidTokenError("invalid timestamp claim")
        return payload
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpiredError() from exc
    except (jwt.PyJWKClientConnectionError, jwt.PyJWKSetError, JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve token signing keys",
        ) from exc
    except (jwt.PyJWTError, ValueError, TypeError, OverflowError) as exc:
        raise InvalidTokenError() from exc


def verify_jwt(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(security),
    ],
) -> dict[str, Any]:
    """FastAPI dependency for endpoint or router authentication.

    Keep this dependency synchronous so JWKS HTTP I/O runs in FastAPI's worker
    thread pool rather than blocking the application's event loop.
    """
    if credentials is None:
        raise MissingTokenError()

    return decode_jwt(credentials.credentials)
