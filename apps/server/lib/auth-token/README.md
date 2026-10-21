# auth-token

Shared JWT verification using `PyJWT[crypto]` and a configured public JWKS URL.
Each application checks its own database permissions after authentication.

Identity signs the token with its private key; a receiving service uses the
public key to check that signature. Sharing public keys lets applications verify
identity without receiving the signing secret. This package is a verifier, not a
token issuer or a database permission service.

All commands run from the repository root.

## Configuration

Configure these environment variables before importing the dependencies:

```dotenv
JWT_ISSUER=https://identity.example.com
JWT_AUDIENCE=your-applications
JWKS_URL=https://identity.example.com/.well-known/jwks.json
JWT_CLOCK_SKEW_SECONDS=5
```

`decode_jwt(token)` verifies the RS256 signature, issuer, audience, expiry,
issued-at, not-before, subject, and token ID. These claims are required. The JWT
header must include `typ: JWT` and a nonempty `kid`. Signing keys come exclusively
from `JWKS_URL`; token-provided key URLs are ignored. The public key set is cached
for 300 seconds and refreshed when a new `kid` appears. Individual signing keys
are not cached indefinitely. See the [PyJWT API reference](https://pyjwt.readthedocs.io/en/stable/api.html).

## Protect endpoints and paths

```python
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from auth_token.dependencies import verify_jwt
from auth_token.exceptions import AuthError

app = FastAPI()


@app.exception_handler(AuthError)
async def handle_auth_error(request: Request, exc: AuthError):
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict(),
        headers={"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else {},
    )


@app.get("/me")
async def me(payload: Annotated[dict[str, Any], Depends(verify_jwt)]):
    return {"user_id": payload["sub"]}


private = APIRouter(prefix="/private", dependencies=[Depends(verify_jwt)])


@private.get("/data")
async def data():
    return {"ok": True}


app.include_router(private)
```

Call protected routes with `Authorization: Bearer ACCESS_TOKEN`. The synchronous
dependency runs JWKS HTTP requests in FastAPI's thread pool. Authentication
failures raise `AuthError` subclasses (401); JWKS connection failures return 503.
Applications build their own permission dependency on top of `verify_jwt`.
The verifier does not query live user bans or sessions. An already-issued token
can therefore remain usable until expiry after logout unless the application
adds a live session check. Identity itself performs that database check after
JWT verification. The library requires the listed standard claims; applications
that depend on an Identity session must validate `sid` in their own contract.

## Tests

The tests use a disposable HTTP JWKS server on loopback and generated RSA keys.
Run from the repository root:

```bash
uv run --frozen --directory apps/server --package auth-token python -B -m unittest discover -s lib/auth-token/tests -v
```
