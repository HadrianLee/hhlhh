from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hmac
import logging
import secrets
from uuid import UUID, uuid4

from auth_token.exceptions import AuthenticationError, InvalidTokenError
from identity.core.email_delivery import IdentityEmailDelivery
from identity.core.issuer import sign_access_token
from identity.core.key_manager import JWT_ACCESS_TOKEN_TTL_SECONDS, KeyManager
from identity.core.security import IdentitySecurity
from identity.db.errors import IdentityConflictError, IdentityNotFoundError, IdentityPolicyError
from identity.db.models.identity import AuthTokenType, User, UserSession
from identity.db.services.passkey_login import PasskeyLoginDbService
from identity.db.services.identity import IdentityDbService

logger = logging.getLogger(__name__)


class IdentityUnavailableError(Exception):
    pass


class IdentityService:
    def __init__(
        self, database: IdentityDbService, key_manager: KeyManager, security: IdentitySecurity,
        email_delivery: IdentityEmailDelivery,
    ) -> None:
        self.db = database
        self.key_manager = key_manager
        self.security = security
        self.email_delivery = email_delivery

    async def register(self, *, email: str, username: str, password: str) -> User:
        password_hash = await self.security.hash_password(password)
        return await self.db.create_user(email=email, username=username, password_hash=password_hash)

    def _tokens(self, user_id: UUID, session_id: UUID, refresh_token: str, expires_at: datetime) -> dict:
        try:
            access_token = sign_access_token(self.key_manager, user_id=user_id, session_id=session_id)
        except RuntimeError as exc:
            raise IdentityUnavailableError("signing is temporarily unavailable") from exc
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": JWT_ACCESS_TOKEN_TTL_SECONDS,
            "session_id": session_id,
            "refresh_expires_at": expires_at,
        }

    async def login(self, *, email: str, password: str) -> dict:
        user = await self.db.get_user_by_email(email)
        valid = await self.security.verify_password(password, user.password_hash if user else None)
        if not valid or user is None or user.is_banned:
            raise AuthenticationError("invalid email or password")
        session_id = uuid4()
        refresh_token = self.security.refresh_token(session_id)
        expires_at = datetime.now(UTC) + timedelta(seconds=self.security.settings.refresh_ttl_seconds)
        tokens = self._tokens(user.user_id, session_id, refresh_token, expires_at)
        try:
            await self.db.create_session(
                user_id=user.user_id, session_id=session_id,
                refresh_token_digest=self.security.refresh_digest(refresh_token), expires_at=expires_at,
                expected_token_version=user.token_version,
            )
        except (IdentityPolicyError, IdentityNotFoundError) as exc:
            raise AuthenticationError("invalid email or password") from exc
        return tokens

    async def refresh(self, token: str) -> dict:
        session_id = self.security.refresh_session_id(token)
        if session_id is None:
            raise InvalidTokenError()
        session = await self.db.get_session(session_id)
        if session is None or session.revoked_at is not None:
            raise InvalidTokenError()
        digest = self.security.refresh_digest(token)
        if not hmac.compare_digest(session.refresh_token_digest, digest):
            await self.db.revoke_session(session_id)
            raise InvalidTokenError("refresh token reuse detected; sign in again")
        principal = await self.db.get_authenticated_user(session.user_id, session_id)
        if principal is None:
            raise InvalidTokenError()
        new_token = self.security.refresh_token(session_id)
        tokens = self._tokens(session.user_id, session_id, new_token, session.expires_at)
        rotated = await self.db.rotate_session_refresh_token(
            session_id=session_id, current_refresh_token_digest=digest,
            new_refresh_token_digest=self.security.refresh_digest(new_token),
        )
        if not rotated:
            await self.db.revoke_session(session_id)
            raise InvalidTokenError("refresh token reuse detected; sign in again")
        return tokens

    async def passkey_options(self, browser_binding: str):
        return await PasskeyLoginDbService(self.db.db).options(browser_binding)

    async def login_passkey(self, *, challenge_id: UUID, browser_binding: str, credential: dict) -> dict:
        session_id = uuid4()
        refresh_token = self.security.refresh_token(session_id)
        expires_at = datetime.now(UTC) + timedelta(seconds=self.security.settings.refresh_ttl_seconds)
        tokens = {}

        def make_session(user: User) -> UserSession:
            tokens.update(self._tokens(user.user_id, session_id, refresh_token, expires_at))
            return UserSession(session_id=session_id, user_id=user.user_id,
                refresh_token_digest=self.security.refresh_digest(refresh_token), expires_at=expires_at)

        await PasskeyLoginDbService(self.db.db).authenticate(challenge_id, browser_binding, credential, make_session)
        return tokens

    async def change_password(self, user: User, session_id: UUID, new_password: str) -> None:
        password_hash = await self.security.hash_password(new_password)
        if not await self.db.change_password(user.user_id, session_id=session_id, expected_hash=user.password_hash, password_hash=password_hash):
            raise IdentityConflictError("credentials changed; sign in again")

    async def reset_password(self, token: str, new_password: str) -> None:
        password_hash = await self.security.hash_password(new_password)
        if not await self.db.reset_password(token_digest=self.security.token_digest(token), password_hash=password_hash):
            raise InvalidTokenError("invalid or expired password reset token")

    async def _deliver(self, *, user: User, email: str, purpose: AuthTokenType, prefix: str = "") -> None:
        token = prefix + secrets.token_urlsafe(32)
        ttl = (self.security.settings.password_reset_ttl_seconds if purpose == AuthTokenType.PASSWORD_RESET
               else self.security.settings.verification_ttl_seconds)
        try:
            await self.db.create_auth_token(
                user_id=user.user_id, token_digest=self.security.token_digest(token), token_type=purpose,
                expires_at=datetime.now(UTC) + timedelta(seconds=ttl), throttle_seconds=60,
            )
        except IdentityPolicyError:
            return
        try:
            await self.email_delivery(email=email, purpose=purpose.value, token=token)
        except Exception:
            logger.error("Identity email delivery failed")

    async def request_password_reset(self, email: str) -> None:
        user = await self.db.get_user_by_email(email)
        if user is not None and not user.is_banned:
            await self._deliver(user=user, email=user.email, purpose=AuthTokenType.PASSWORD_RESET)

    async def request_verification(self, email: str) -> None:
        user = await self.db.get_user_by_email(email)
        if user is not None and not user.is_banned and user.verified_at is None:
            await self._deliver(user=user, email=user.email, purpose=AuthTokenType.VERIFY_ACCOUNT, prefix="primary.")

    async def request_secondary_verification(self, user: User, email_id: UUID) -> None:
        emails = await self.db.list_secondary_emails(user.user_id)
        email = next((row for row in emails if row.secondary_email_id == email_id), None)
        if email is None:
            raise IdentityNotFoundError("email not found")
        if not email.is_verified:
            await self._deliver(user=user, email=email.email, purpose=AuthTokenType.VERIFY_ACCOUNT, prefix=f"{email_id}.")

    async def confirm_email(self, token: str) -> None:
        try:
            prefix, _ = token.split(".", 1)
            email_id = None if prefix == "primary" else UUID(prefix)
        except ValueError as exc:
            raise InvalidTokenError("invalid verification token") from exc
        if not await self.db.confirm_email(token_digest=self.security.token_digest(token), email_id=email_id):
            raise InvalidTokenError("invalid or expired verification token")

    async def promote_secondary_email(self, user: User, session_id: UUID, email_id: UUID) -> User:
        return await self.db.promote_secondary_email(user.user_id, email_id, session_id=session_id, expected_hash=user.password_hash)
