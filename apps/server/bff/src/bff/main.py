import asyncio
from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, Request
from fastapi.openapi.utils import get_openapi
import httpx
from sqlalchemy import select

from bff.api.dependencies import AuthRateLimiter
from bff.api.router import router
from bff.core.identity import IdentityClient
from bff.core.middleware import BrowserSecurityMiddleware
from bff.core.security import BffSecurity, BffSettings
from bff.db.models.session import BrowserSession
from bff.db.services.base import Database
from bff.db.services.session import SessionDbService
from bff.db.session import create_session_factory
from bff.exception_handlers import register_exception_handlers
from bff.services.session import SessionService

logger = logging.getLogger(__name__)


async def cleanup_loop(service: SessionService) -> None:
    while True:
        await asyncio.sleep(service.security.settings.cleanup_interval_seconds)
        try:
            await service.cleanup()
        except Exception as exc:
            logger.error("BFF session cleanup failed (%s)", type(exc).__name__)


def create_app(*, settings: BffSettings | None = None, database: Database | None = None,
               http_client: httpx.AsyncClient | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configured = settings or BffSettings.from_env()
        engine = None
        own_client = http_client is None
        client = http_client or httpx.AsyncClient(timeout=httpx.Timeout(10, connect=3),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20), follow_redirects=False, trust_env=False)
        try:
            if database is None:
                engine, factory = create_session_factory(configured.database_url)
                configured_database = Database(factory)
            else:
                configured_database = database
            security = BffSecurity(configured)
            service = SessionService(SessionDbService(configured_database), IdentityClient(client, configured), security)
            app.state.security = security
            app.state.session_service = service
            app.state.auth_rate_limiter = AuthRateLimiter()
            task = asyncio.create_task(cleanup_loop(service))
            try:
                yield
            finally:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                for name in ("security", "session_service", "auth_rate_limiter"):
                    delattr(app.state, name)
        finally:
            if own_client:
                await client.aclose()
            if engine is not None:
                await engine.dispose()

    app = FastAPI(title="Browser BFF", version="0.1.0", lifespan=lifespan)
    register_exception_handlers(app)
    app.add_middleware(BrowserSecurityMiddleware)
    app.include_router(router, prefix="/api")

    def openapi():
        if app.openapi_schema is None:
            schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
            for path, operations in schema["paths"].items():
                if path.startswith("/api/"):
                    for method, operation in operations.items():
                        if method in {"post", "put", "patch", "delete"}:
                            operation.setdefault("parameters", []).append({
                                "name": "X-CSRF-Token", "in": "header", "required": True,
                                "description": "Token from /api/auth/csrf or the latest login response. Origin must match BFF_PUBLIC_ORIGIN.",
                                "schema": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                            })
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi

    @app.get("/health", tags=["health"])
    async def health():
        return {"status": "OK"}

    @app.get("/ready", tags=["health"])
    async def ready(request: Request):
        async with request.app.state.session_service.database.db.session() as session:
            await session.execute(select(BrowserSession.session_id).limit(1))
        return {"status": "OK"}

    return app


app = create_app()
