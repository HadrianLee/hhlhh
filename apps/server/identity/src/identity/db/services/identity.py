from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import delete, distinct, exists, select, update
from sqlalchemy.exc import IntegrityError

from ..errors import IdentityConflictError, IdentityNotFoundError, IdentityPolicyError
from ..models.identity import (
    AuthToken,
    AuthTokenType,
    Permission,
    Role,
    RoleAuditAction,
    RoleAuditLog,
    RolePermission,
    User,
    UserRole,
    UserSession,
    UserSecondaryEmail,
)
from .base import Database
from .security import require_recent_mfa


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _validate_hex_sha256(value: str, *, field_name: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64:
        raise ValueError(f"{field_name} must be a 64-character SHA-256 hex digest")
    try:
        if len(bytes.fromhex(normalized)) != 32:
            raise ValueError("invalid digest length")
    except ValueError as exc:
        raise ValueError(f"{field_name} must contain hexadecimal characters only") from exc
    return normalized

class IdentityDbService:
    """Transaction-scoped identity persistence facade for API/service code.

    The caller passes already-hashed passwords and already-computed token digests.
    Crypto policy stays outside the database layer.
    """

    def __init__(self, database: Database) -> None:
        self.db = database

    async def create_user(
        self,
        *,
        email: str,
        username: str,
        password_hash: str,
    ) -> User:
        user = User(
            email=_normalize_email(email),
            username=username.strip(),
            password_hash=password_hash,
        )
        try:
            async with self.db.transaction() as session:
                session.add(user)
                await session.flush()
            return user
        except IntegrityError as exc:
            raise IdentityConflictError("email or username already exists") from exc

    async def get_user(self, user_id: UUID) -> User | None:
        async with self.db.session() as session:
            return await session.get(User, user_id)

    async def get_user_by_email(self, email: str) -> User | None:
        async with self.db.session() as session:
            return await session.scalar(
                select(User).where(User.email == _normalize_email(email))
            )

    async def set_user_banned(
        self, *, user_id: UUID, is_banned: bool, actor_user_id: UUID, actor_session_id: UUID,
    ) -> User:
        now = _utcnow()
        async with self.db.transaction() as session:
            await require_recent_mfa(session, actor_user_id, actor_session_id, target_user_id=user_id)
            user = await session.get(User, user_id, with_for_update=True)
            if user is None:
                raise IdentityNotFoundError("user not found")

            changed = user.is_banned != is_banned
            user.is_banned = is_banned
            if changed:
                user.token_version += 1

            if is_banned:
                await session.execute(
                    update(UserSession)
                    .where(
                        UserSession.user_id == user_id,
                        UserSession.revoked_at.is_(None),
                    )
                    .values(revoked_at=now)
                )

            await session.flush()
            await session.refresh(user)
            return user

    async def create_auth_token(
        self,
        *,
        user_id: UUID,
        token_digest: str,
        token_type: AuthTokenType,
        expires_at: datetime,
        throttle_seconds: int = 0,
    ) -> AuthToken:
        token_digest = _validate_hex_sha256(token_digest, field_name="token_digest")
        token = AuthToken(
            user_id=user_id,
            token_digest=token_digest,
            token_type=token_type.value,
            expires_at=expires_at,
        )

        try:
            async with self.db.transaction() as session:
                if await session.get(User, user_id, with_for_update=True) is None:
                    raise IdentityNotFoundError("user not found")

                if throttle_seconds and await session.scalar(select(AuthToken.auth_token_id).where(
                    AuthToken.user_id == user_id, AuthToken.token_type == token_type.value,
                    AuthToken.created_at > _utcnow() - timedelta(seconds=throttle_seconds),
                ).limit(1)) is not None:
                    raise IdentityPolicyError("a token was recently requested")

                await session.execute(
                    delete(AuthToken).where(
                        AuthToken.user_id == user_id,
                        AuthToken.token_type == token_type.value,
                    )
                )
                session.add(token)
                await session.flush()
            return token
        except IntegrityError as exc:
            raise IdentityConflictError("auth token digest already exists") from exc

    async def consume_auth_token(
        self,
        *,
        token_digest: str,
        token_type: AuthTokenType,
        now: datetime | None = None,
    ) -> AuthToken | None:
        token_digest = _validate_hex_sha256(token_digest, field_name="token_digest")
        now = now or _utcnow()

        async with self.db.transaction() as session:
            token = await session.scalar(
                delete(AuthToken).where(
                    AuthToken.token_digest == token_digest,
                    AuthToken.token_type == token_type.value,
                ).returning(AuthToken)
            )
            if token is None:
                return None

            if _as_utc(token.expires_at) <= _as_utc(now):
                return None

            await session.flush()
            return token

    async def create_session(
        self,
        *,
        user_id: UUID,
        refresh_token_digest: str,
        expires_at: datetime,
        session_id: UUID | None = None,
        expected_token_version: int | None = None,
    ) -> UserSession:
        refresh_token_digest = _validate_hex_sha256(
            refresh_token_digest,
            field_name="refresh_token_digest",
        )
        user_session = UserSession(
            session_id=session_id or uuid4(),
            user_id=user_id,
            refresh_token_digest=refresh_token_digest,
            expires_at=expires_at,
        )

        try:
            async with self.db.transaction() as session:
                user = await session.get(User, user_id, with_for_update=True)
                if user is None:
                    raise IdentityNotFoundError("user not found")
                if user.is_banned:
                    raise IdentityPolicyError("cannot create a session for a banned user")
                if expected_token_version is not None and user.token_version != expected_token_version:
                    raise IdentityPolicyError("credentials changed during authentication")

                session.add(user_session)
                await session.flush()
            return user_session
        except IntegrityError as exc:
            raise IdentityConflictError("refresh token digest already exists") from exc

    async def get_session(self, session_id: UUID) -> UserSession | None:
        async with self.db.session() as session:
            return await session.get(UserSession, session_id)

    async def get_active_session_by_refresh_digest(
        self,
        *,
        refresh_token_digest: str,
        now: datetime | None = None,
    ) -> UserSession | None:
        refresh_token_digest = _validate_hex_sha256(
            refresh_token_digest,
            field_name="refresh_token_digest",
        )
        now = now or _utcnow()

        async with self.db.session() as session:
            return await session.scalar(
                select(UserSession).where(
                    UserSession.refresh_token_digest == refresh_token_digest,
                    UserSession.revoked_at.is_(None),
                    UserSession.expires_at > now,
                )
            )

    async def rotate_session_refresh_token(
        self,
        *,
        session_id: UUID,
        current_refresh_token_digest: str,
        new_refresh_token_digest: str,
        new_expires_at: datetime | None = None,
        now: datetime | None = None,
    ) -> bool:
        current_refresh_token_digest = _validate_hex_sha256(
            current_refresh_token_digest,
            field_name="current_refresh_token_digest",
        )
        new_refresh_token_digest = _validate_hex_sha256(
            new_refresh_token_digest,
            field_name="new_refresh_token_digest",
        )
        now = now or _utcnow()

        values: dict[str, object] = {
            "refresh_token_digest": new_refresh_token_digest,
            "last_used_at": now,
        }
        if new_expires_at is not None:
            values["expires_at"] = new_expires_at

        try:
            async with self.db.transaction() as session:
                result = await session.execute(
                    update(UserSession)
                    .where(
                        UserSession.session_id == session_id,
                        UserSession.refresh_token_digest == current_refresh_token_digest,
                        UserSession.revoked_at.is_(None),
                        UserSession.expires_at > now,
                    )
                    .values(**values)
                )
                return result.rowcount == 1
        except IntegrityError as exc:
            raise IdentityConflictError("new refresh token digest already exists") from exc

    async def revoke_session(self, session_id: UUID, *, now: datetime | None = None) -> bool:
        now = now or _utcnow()
        async with self.db.transaction() as session:
            result = await session.execute(
                update(UserSession)
                .where(
                    UserSession.session_id == session_id,
                    UserSession.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            return result.rowcount == 1

    async def revoke_all_user_sessions(
        self, user_id: UUID, *, now: datetime | None = None,
        actor_user_id: UUID | None = None, actor_session_id: UUID | None = None,
    ) -> int:
        if (actor_user_id is None) != (actor_session_id is None):
            raise ValueError("provide both actor user and session IDs")
        now = now or _utcnow()
        async with self.db.transaction() as session:
            # Own-account logout remains available without a challenge.
            if actor_user_id is not None:
                await require_recent_mfa(session, actor_user_id, actor_session_id, target_user_id=user_id)
            result = await session.execute(
                update(UserSession)
                .where(
                    UserSession.user_id == user_id,
                    UserSession.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            return int(result.rowcount or 0)

    async def list_user_permissions(self, user_id: UUID) -> set[str]:
        async with self.db.session() as session:
            actions = await session.scalars(
                select(distinct(Permission.action))
                .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
                .join(UserRole, UserRole.role_id == RolePermission.role_id)
                .where(UserRole.user_id == user_id)
            )
            return set(actions)

    async def has_permission(self, *, user_id: UUID, action: str) -> bool:
        async with self.db.session() as session:
            stmt = select(
                exists().where(
                    UserRole.user_id == user_id,
                    UserRole.role_id == RolePermission.role_id,
                    RolePermission.permission_id == Permission.permission_id,
                    Permission.action == action,
                )
            )
            return bool(await session.scalar(stmt))

    async def assign_role(
        self,
        *,
        user_id: UUID,
        role_name: str | None = None,
        actor_user_id: UUID,
        actor_session_id: UUID,
        role_id: UUID | None = None,
    ) -> bool:
        if (role_id is None) == (role_name is None):
            raise ValueError("provide exactly one role id or role name")
        async with self.db.transaction() as session:
            await require_recent_mfa(session, actor_user_id, actor_session_id, target_user_id=user_id)
            user = await session.get(User, user_id, with_for_update=True)
            if user is None:
                raise IdentityNotFoundError("target user not found")
            if await session.get(User, actor_user_id) is None:
                raise IdentityNotFoundError("actor user not found")

            role = await session.scalar(select(Role).where(Role.role_id == role_id if role_id is not None else Role.name == role_name))
            if role is None:
                raise IdentityNotFoundError("role not found")

            already_assigned = await session.get(UserRole, (user_id, role.role_id))
            if already_assigned is not None:
                return False

            session.add(
                UserRole(
                    user_id=user_id,
                    role_id=role.role_id,
                    assigned_by_user_id=actor_user_id,
                )
            )
            session.add(
                RoleAuditLog(
                    actor_user_id=actor_user_id,
                    target_user_id=user_id,
                    action_type=RoleAuditAction.ASSIGNED.value,
                    role_id=role.role_id,
                    role_name_snapshot=role.name,
                    changes={"assigned": True},
                )
            )
            user.token_version += 1
            await session.flush()
            return True

    async def get_authenticated_user(self, user_id: UUID, session_id: UUID) -> tuple[User, UserSession] | None:
        async with self.db.session() as session:
            row = (await session.execute(
                select(User, UserSession).join(UserSession, UserSession.user_id == User.user_id).where(
                    User.user_id == user_id, UserSession.session_id == session_id,
                    User.is_banned.is_(False), UserSession.revoked_at.is_(None),
                    UserSession.expires_at > _utcnow(),
                )
            )).first()
            return (row[0], row[1]) if row is not None else None

    async def update_username(self, user_id: UUID, username: str) -> User:
        try:
            async with self.db.transaction() as session:
                user = await session.get(User, user_id)
                if user is None:
                    raise IdentityNotFoundError("user not found")
                user.username = username.strip()
                await session.flush()
                await session.refresh(user)
                return user
        except IntegrityError as exc:
            raise IdentityConflictError("username already exists") from exc

    async def list_sessions(self, user_id: UUID, *, limit: int = 50, offset: int = 0) -> list[UserSession]:
        async with self.db.session() as session:
            return list(await session.scalars(select(UserSession).where(UserSession.user_id == user_id)
                .order_by(UserSession.created_at.desc(), UserSession.session_id).limit(limit).offset(offset)))

    async def change_password(self, user_id: UUID, *, session_id: UUID, expected_hash: str, password_hash: str) -> bool:
        async with self.db.transaction() as session:
            await require_recent_mfa(session, user_id, session_id)
            result = await session.execute(update(User).where(
                User.user_id == user_id, User.password_hash == expected_hash, User.is_banned.is_(False),
            ).values(password_hash=password_hash, token_version=User.token_version + 1))
            if result.rowcount != 1:
                return False
            await session.execute(update(UserSession).where(
                UserSession.user_id == user_id, UserSession.revoked_at.is_(None),
            ).values(revoked_at=_utcnow()))
            await session.execute(delete(AuthToken).where(
                AuthToken.user_id == user_id, AuthToken.token_type == AuthTokenType.PASSWORD_RESET.value,
            ))
            return True

    async def reset_password(self, *, token_digest: str, password_hash: str) -> bool:
        async with self.db.transaction() as session:
            token_digest = _validate_hex_sha256(token_digest, field_name="token_digest")
            user_id = await session.scalar(select(AuthToken.user_id).where(
                AuthToken.token_digest == token_digest, AuthToken.token_type == AuthTokenType.PASSWORD_RESET.value,
            ))
            if user_id is None:
                return False
            user = await session.get(User, user_id, with_for_update=True)
            token = await session.scalar(delete(AuthToken).where(
                AuthToken.token_digest == token_digest,
                AuthToken.token_type == AuthTokenType.PASSWORD_RESET.value,
            ).returning(AuthToken))
            if token is None or _as_utc(token.expires_at) <= _utcnow():
                return False
            if user is None or user.is_banned:
                return False
            user.password_hash = password_hash
            user.token_version += 1
            await session.execute(update(UserSession).where(
                UserSession.user_id == user.user_id, UserSession.revoked_at.is_(None),
            ).values(revoked_at=_utcnow()))
            return True

    async def list_secondary_emails(self, user_id: UUID) -> list[UserSecondaryEmail]:
        async with self.db.session() as session:
            return list(await session.scalars(select(UserSecondaryEmail).where(
                UserSecondaryEmail.user_id == user_id,
            ).order_by(UserSecondaryEmail.created_at, UserSecondaryEmail.secondary_email_id)))

    async def add_secondary_email(self, user_id: UUID, email: str, *, session_id: UUID) -> UserSecondaryEmail:
        email = _normalize_email(email)
        try:
            async with self.db.transaction() as session:
                await require_recent_mfa(session, user_id, session_id)
                if await session.scalar(select(User.user_id).where(User.email == email)) is not None:
                    raise IdentityConflictError("email is already in use")
                row = UserSecondaryEmail(user_id=user_id, email=email)
                session.add(row)
                await session.flush()
                return row
        except IntegrityError as exc:
            raise IdentityConflictError("email is already in use") from exc

    async def delete_secondary_email(self, user_id: UUID, email_id: UUID, *, session_id: UUID) -> bool:
        async with self.db.transaction() as session:
            await require_recent_mfa(session, user_id, session_id)
            result = await session.execute(delete(UserSecondaryEmail).where(
                UserSecondaryEmail.user_id == user_id, UserSecondaryEmail.secondary_email_id == email_id,
            ).returning(UserSecondaryEmail.secondary_email_id))
            return result.scalar_one_or_none() is not None

    async def confirm_email(self, *, token_digest: str, email_id: UUID | None) -> bool:
        async with self.db.transaction() as session:
            token_digest = _validate_hex_sha256(token_digest, field_name="token_digest")
            user_id = await session.scalar(select(AuthToken.user_id).where(
                AuthToken.token_digest == token_digest, AuthToken.token_type == AuthTokenType.VERIFY_ACCOUNT.value,
            ))
            if user_id is None:
                return False
            user = await session.get(User, user_id, with_for_update=True)
            token = await session.scalar(delete(AuthToken).where(
                AuthToken.token_digest == token_digest,
                AuthToken.token_type == AuthTokenType.VERIFY_ACCOUNT.value,
            ).returning(AuthToken))
            if token is None or _as_utc(token.expires_at) <= _utcnow():
                return False
            if user is None or user.is_banned:
                return False
            if email_id is None:
                user.verified_at = user.verified_at or _utcnow()
            else:
                email = await session.get(UserSecondaryEmail, email_id)
                if email is None or email.user_id != user.user_id:
                    return False
                email.is_verified = True
                email.verified_at = email.verified_at or _utcnow()
            return True

    async def promote_secondary_email(self, user_id: UUID, email_id: UUID, *, session_id: UUID, expected_hash: str) -> User:
        try:
            async with self.db.transaction() as session:
                user = await require_recent_mfa(session, user_id, session_id)
                email = await session.get(UserSecondaryEmail, email_id, with_for_update=True)
                if user is None or email is None or email.user_id != user_id:
                    raise IdentityNotFoundError("email not found")
                if user.is_banned or user.password_hash != expected_hash or not email.is_verified:
                    raise IdentityPolicyError("a verified email and current credentials are required")
                old_email, old_verified_at = user.email, user.verified_at
                user.email, user.verified_at = email.email, email.verified_at
                user.token_version += 1
                await session.delete(email)
                await session.flush()
                session.add(UserSecondaryEmail(
                    user_id=user_id, email=old_email,
                    is_verified=old_verified_at is not None, verified_at=old_verified_at,
                ))
                await session.execute(delete(AuthToken).where(AuthToken.user_id == user_id))
                await session.execute(update(UserSession).where(
                    UserSession.user_id == user_id, UserSession.revoked_at.is_(None),
                ).values(revoked_at=_utcnow()))
                await session.flush()
                await session.refresh(user)
                return user
        except IntegrityError as exc:
            raise IdentityConflictError("email is already in use") from exc

    async def remove_role(
        self,
        *,
        user_id: UUID,
        role_name: str | None = None,
        actor_user_id: UUID,
        actor_session_id: UUID,
        role_id: UUID | None = None,
    ) -> bool:
        if (role_id is None) == (role_name is None):
            raise ValueError("provide exactly one role id or role name")
        async with self.db.transaction() as session:
            await require_recent_mfa(session, actor_user_id, actor_session_id, target_user_id=user_id)
            user = await session.get(User, user_id, with_for_update=True)
            if user is None:
                raise IdentityNotFoundError("target user not found")
            if await session.get(User, actor_user_id) is None:
                raise IdentityNotFoundError("actor user not found")

            role = await session.scalar(select(Role).where(Role.role_id == role_id if role_id is not None else Role.name == role_name))
            if role is None:
                raise IdentityNotFoundError("role not found")

            membership = await session.get(UserRole, (user_id, role.role_id))
            if membership is None:
                return False

            await session.delete(membership)
            session.add(
                RoleAuditLog(
                    actor_user_id=actor_user_id,
                    target_user_id=user_id,
                    action_type=RoleAuditAction.REMOVED.value,
                    role_id=role.role_id,
                    role_name_snapshot=role.name,
                    changes={"assigned": False},
                )
            )
            user.token_version += 1
            await session.flush()
            return True
