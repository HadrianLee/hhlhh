from dataclasses import dataclass, field
from datetime import timedelta
import logging
from uuid import UUID, uuid4

from cryptography.fernet import InvalidToken
from sqlalchemy.ext.asyncio import AsyncSession

from bff.core.identity import IdentityClient, TokenResponse
from bff.core.security import BffSecurity
from bff.db.models.session import BrowserSession, SessionEventType
from bff.db.services.session import SessionDbService, aware, utcnow
from bff.exceptions import BffError, SessionInvalidError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Principal:
    session: BrowserSession
    access_token: str = field(repr=False)


class SessionService:
    def __init__(self, database: SessionDbService, identity: IdentityClient, security: BffSecurity) -> None:
        self.database = database
        self.identity = identity
        self.security = security

    @staticmethod
    def token_context(row: BrowserSession, kind: str) -> str:
        return f"{row.cookie_digest}:{row.user_id}:{row.identity_session_id}:{kind}"

    def access_token(self, row: BrowserSession) -> str:
        return self.security.decrypt(row.access_token_encrypted, context=self.token_context(row, "access"))

    def refresh_token(self, row: BrowserSession) -> str:
        return self.security.decrypt(row.refresh_token_encrypted, context=self.token_context(row, "refresh"))

    def apply_tokens(self, row: BrowserSession, tokens: TokenResponse, requested_at) -> None:
        if tokens.session_id != row.identity_session_id:
            raise BffError(502, "Identity changed the session unexpectedly")
        if tokens.refresh_expires_at <= requested_at:
            raise BffError(502, "Identity returned an expired session")
        row.access_token_encrypted = self.security.encrypt(tokens.access_token.get_secret_value(), context=self.token_context(row, "access"))
        row.refresh_token_encrypted = self.security.encrypt(tokens.refresh_token.get_secret_value(), context=self.token_context(row, "refresh"))
        row.access_expires_at = requested_at + timedelta(seconds=tokens.expires_in)
        row.refresh_expires_at = tokens.refresh_expires_at
        row.expires_at = min(aware(row.expires_at), tokens.refresh_expires_at)

    async def login(self, *, email: str, password: str, previous_cookie: str | None,
                    ip_address: str | None, user_agent: str | None) -> tuple[BrowserSession, str]:
        requested_at = utcnow()
        tokens = await self.identity.tokens("/api/auth/login", {"email": email, "password": password})
        return await self.create_browser_session(tokens, requested_at, previous_cookie=previous_cookie,
                                                 ip_address=ip_address, user_agent=user_agent)

    async def login_passkey(self, *, challenge_id: UUID, credential: dict, browser_binding: str,
                            previous_cookie: str | None, ip_address: str | None,
                            user_agent: str | None) -> tuple[BrowserSession, str]:
        requested_at = utcnow()
        tokens = await self.identity.tokens("/api/auth/passkey/login", {
            "challenge_id": str(challenge_id), "credential": credential, "browser_binding": browser_binding,
        })
        return await self.create_browser_session(tokens, requested_at, previous_cookie=previous_cookie,
                                                 ip_address=ip_address, user_agent=user_agent)

    async def create_browser_session(self, tokens: TokenResponse, requested_at, *, previous_cookie: str | None,
                                     ip_address: str | None, user_agent: str | None) -> tuple[BrowserSession, str]:
        access_token = tokens.access_token.get_secret_value()
        try:
            user_id = await self.identity.user(access_token)
            cookie = self.security.new_secret()
            row = BrowserSession(
                session_id=uuid4(), user_id=user_id, identity_session_id=tokens.session_id,
                cookie_digest=self.security.session_digest(cookie), created_at=requested_at, last_used_at=requested_at,
                expires_at=min(requested_at + timedelta(seconds=self.security.settings.session_ttl_seconds), tokens.refresh_expires_at),
                ip_address=ip_address, user_agent=user_agent,
            )
            if row.expires_at <= utcnow():
                raise BffError(502, "Identity returned an expired session")
            self.apply_tokens(row, tokens, requested_at)
            previous_digest = self.security.session_digest(previous_cookie) if self.security.valid_secret(previous_cookie) else None
            await self.database.create(row, previous_digest=previous_digest)
        except Exception:
            try:
                await self.identity.request("POST", "/api/auth/logout", access_token=access_token)
            except BffError:
                pass
            raise
        return row, cookie

    async def refresh(self, session: AsyncSession, row: BrowserSession) -> None:
        requested_at = utcnow()
        token = self.refresh_token(row)
        try:
            tokens = await self.identity.tokens("/api/auth/refresh", {"refresh_token": token})
            self.apply_tokens(row, tokens, requested_at)
        except BffError as exc:
            # A timeout may happen after identity rotated the refresh token. Never retry
            # the old token for browser traffic; revoke this local session instead.
            if exc.status_code in {400, 401, 403, 422} or exc.status_code >= 500:
                self.database.revoke(session, row, "refresh_failed", pending=exc.status_code >= 500)
            raise
        self.database.event(session, row, SessionEventType.REFRESHED)

    async def authenticate(self, cookie: str | None) -> Principal:
        if not self.security.valid_secret(cookie):
            raise SessionInvalidError()
        failure = None
        principal = None
        # The lock spans refresh and persistence, across all workers/replicas.
        async with self.database.locked(digest=self.security.session_digest(cookie)) as (session, row):
            now = utcnow()
            if row is None or row.revoked_at is not None:
                failure = SessionInvalidError()
            elif (aware(row.expires_at) <= now or
                  aware(row.last_used_at) + timedelta(seconds=self.security.settings.session_idle_seconds) <= now):
                self.database.revoke(session, row, "expired")
                failure = SessionInvalidError("Session expired")
            else:
                try:
                    refreshed = aware(row.access_expires_at) <= now + timedelta(seconds=self.security.settings.refresh_margin_seconds)
                    if refreshed:
                        await self.refresh(session, row)
                    access_token = self.access_token(row)
                    # Downstream services verify the JWT and enforce their own permissions.
                    row.last_used_at = max(utcnow(), aware(row.last_used_at))
                    principal = Principal(row, access_token)
                except (InvalidToken, UnicodeError):
                    self.database.revoke(session, row, "invalid_storage", pending=False)
                    failure = SessionInvalidError()
                except BffError as exc:
                    if exc.status_code in {400, 401, 403, 422}:
                        self.database.revoke(session, row, "identity_rejected", pending=False)
                        failure = SessionInvalidError()
                    else:
                        if row.revoked_at is not None:
                            exc.clear_session = True
                        failure = exc
        # Raise after commit so expiry/revocation changes survive an error response.
        if failure is not None:
            raise failure
        return principal

    async def finish_revocation(self, session: AsyncSession, row: BrowserSession) -> None:
        if not row.revocation_pending:
            return
        if aware(row.refresh_expires_at) <= utcnow():
            self.database.clear_tokens(row)
            return
        try:
            if aware(row.access_expires_at) <= utcnow() + timedelta(seconds=self.security.settings.refresh_margin_seconds):
                requested_at = utcnow()
                tokens = await self.identity.tokens("/api/auth/refresh", {
                    "refresh_token": self.refresh_token(row),
                })
                self.apply_tokens(row, tokens, requested_at)
            response = await self.identity.request("POST", "/api/auth/logout",
                access_token=self.access_token(row))
            if response.status_code not in {200, 204, 401}:
                self.identity.require_success(response)
                raise BffError(502, "Identity returned an invalid logout response")
        except BffError as exc:
            if exc.status_code not in {400, 401, 403, 422}:
                return
        except (InvalidToken, UnicodeError):
            logger.error("Cannot decrypt credentials for a revoked BFF session")
        self.database.clear_tokens(row)
        self.database.event(session, row, SessionEventType.IDENTITY_REVOKED)

    async def logout(self, cookie: str | None) -> None:
        if not self.security.valid_secret(cookie):
            return
        async with self.database.locked(digest=self.security.session_digest(cookie)) as (session, row):
            if row is not None:
                self.database.revoke(session, row, "logout")
                await self.finish_revocation(session, row)

    async def logout_all(self, principal: Principal) -> None:
        failure = None
        try:
            response = await self.identity.request("POST", "/api/auth/logout-all", access_token=principal.access_token)
            self.identity.require_success(response)
        except BffError as exc:
            failure = exc
        await self.database.revoke_user(principal.session.user_id, reason="logout_all", pending=failure is not None)
        if failure is not None:
            failure.clear_session = True
            raise failure

    async def revoke_session(self, principal: Principal, session_id: UUID) -> None:
        async with self.database.locked(session_id=session_id, user_id=principal.session.user_id) as (session, row):
            if row is None:
                raise BffError(404, "Session not found")
            self.database.revoke(session, row, "user_revoked")
            await self.finish_revocation(session, row)

    async def cleanup(self) -> None:
        candidates = await self.database.cleanup_candidates(idle_seconds=self.security.settings.session_idle_seconds)
        for session_id in candidates:
            async with self.database.locked(session_id=session_id) as (session, row):
                if row is None:
                    continue
                now = utcnow()
                if row.revoked_at is None and (aware(row.expires_at) <= now or
                        aware(row.last_used_at) + timedelta(seconds=self.security.settings.session_idle_seconds) <= now):
                    self.database.revoke(session, row, "expired")
                await self.finish_revocation(session, row)
        await self.database.purge(self.security.settings.retention_seconds)
