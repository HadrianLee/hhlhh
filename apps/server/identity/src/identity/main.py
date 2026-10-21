import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from email_delivery import SmtpMailService
from identity.api.router import router
from identity.exception_handlers import register_auth_exception_handlers
from identity.core.key_manager import KeyManager
from identity.db.services.base import Database
from identity.db.services.key_manager import KeyManagerDbService
from identity.db.services.identity import IdentityDbService
from identity.core.security import IdentitySecurity, IdentitySettings
from identity.core.email_delivery import IdentityMailDelivery
from identity.api.dependencies import AuthRateLimiter

JWT_KEY_ROTATION_INTERVAL_SECONDS = int(os.environ["JWT_KEY_ROTATION_INTERVAL_SECONDS"])
logger = logging.getLogger(__name__)

async def rotation_loop(manager: KeyManager) -> None:
    delay = JWT_KEY_ROTATION_INTERVAL_SECONDS
    while True:
        await asyncio.sleep(delay)
        try:
            await manager.rotate()
        except Exception:
            logger.exception("Signing key rotation failed; retrying")
            delay = min(5, JWT_KEY_ROTATION_INTERVAL_SECONDS)
        else:
            delay = JWT_KEY_ROTATION_INTERVAL_SECONDS

@asynccontextmanager
async def lifespan(app: FastAPI):
    for setting in ("SMTP_HOST", "SMTP_PORT", "IDENTITY_EMAIL_FROM", "BFF_PUBLIC_ORIGIN"):
        if not os.environ.get(setting, "").strip():
            raise RuntimeError(f"{setting} is required for identity email delivery")
    try:
        email_delivery = IdentityMailDelivery(
            SmtpMailService(hostname=os.environ["SMTP_HOST"],
                            port=int(os.environ["SMTP_PORT"])),
            fr=os.environ["IDENTITY_EMAIL_FROM"],
            public_origin=os.environ["BFF_PUBLIC_ORIGIN"],
        )
    except ValueError as exc:
        raise RuntimeError("Invalid identity email delivery configuration") from exc
    security = IdentitySecurity(IdentitySettings.from_env())
    database = Database()
    manager = KeyManager(KeyManagerDbService(database))
    await manager.rotate()
    app.state.key_manager = manager
    app.state.identity_db = IdentityDbService(database)
    app.state.identity_security = security
    app.state.identity_rate_limiter = AuthRateLimiter()
    app.state.identity_email_delivery = email_delivery
    task = asyncio.create_task(rotation_loop(manager))

    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        finally:
            del app.state.key_manager
            del app.state.identity_db
            del app.state.identity_security
            del app.state.identity_rate_limiter
            del app.state.identity_email_delivery

app = FastAPI(lifespan=lifespan)
register_auth_exception_handlers(app)
app.include_router(router, prefix="/api")

@app.get("/.well-known/jwks.json", include_in_schema=False)
async def jwks(request: Request) -> JSONResponse:
    return JSONResponse(
        content=await request.app.state.key_manager.jwks(),
        media_type="application/jwk-set+json",
    )

@app.get("/health", tags=["health"])
async def health_check():
    return {"status": "OK"}

@app.get("/")
async def root():
    return {"hello": "world"}
