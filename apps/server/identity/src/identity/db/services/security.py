from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from identity.core.challenges import MFA_TTL_SECONDS, ChallengeError
from identity.db.models.challenge import AuthChallenge, ChallengePurpose
from identity.db.models.identity import User, UserSession


async def require_recent_mfa(
    session: AsyncSession, user_id: UUID, session_id: UUID, *, target_user_id: UUID | None = None,
) -> User:
    """Recheck session and challenge while the security change is being committed."""
    # Lock actor and target in a consistent order for concurrent admin changes.
    users = {row.user_id: row for row in await session.scalars(select(User)
        .where(User.user_id.in_({user_id, target_user_id} - {None}))
        .order_by(User.user_id).with_for_update())}
    user = users.get(user_id)
    login = await session.get(UserSession, session_id, with_for_update=True)
    now = datetime.now(UTC)
    expires_at = login.expires_at if login else None
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if (user is None or user.is_banned or login is None or login.user_id != user_id
            or login.revoked_at is not None or expires_at <= now):
        raise ChallengeError(401, "The current session is no longer active")
    proof = await session.scalar(select(AuthChallenge).where(
        AuthChallenge.user_id == user_id, AuthChallenge.session_id == session_id,
        AuthChallenge.purpose.in_([ChallengePurpose.EMAIL_OTP, ChallengePurpose.PASSKEY_AUTHENTICATION]),
        AuthChallenge.cancelled_at.is_(None),
        AuthChallenge.verified_at > now - timedelta(seconds=MFA_TTL_SECONDS),
    ).order_by(AuthChallenge.verified_at.desc()).limit(1).with_for_update())
    if proof is None:
        raise ChallengeError(403, "Complete a recent MFA challenge for this session")
    return user
