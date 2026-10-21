from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import AsyncIterator
from uuid import UUID

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from bff.db.models.session import BrowserSession, SessionEvent, SessionEventType
from .base import Database


def utcnow() -> datetime:
    return datetime.now(UTC)


def aware(value: datetime) -> datetime:
    # PostgreSQL supplies aware datetimes; SQLite test sessions do not.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class SessionDbService:
    def __init__(self, database: Database) -> None:
        self.db = database

    @staticmethod
    def event(session: AsyncSession, row: BrowserSession, event_type: SessionEventType, reason: str | None = None) -> None:
        session.add(SessionEvent(session_id=row.session_id, event_type=event_type.value, reason=reason))

    @staticmethod
    def clear_tokens(row: BrowserSession) -> None:
        row.access_token_encrypted = None
        row.refresh_token_encrypted = None
        row.revocation_pending = False

    def revoke(self, session: AsyncSession, row: BrowserSession, reason: str, *, pending: bool = True) -> None:
        if row.revoked_at is None:
            row.revoked_at = utcnow()
            row.revoke_reason = reason
            self.event(session, row, SessionEventType.REVOKED, reason)
        row.revocation_pending = pending and row.refresh_token_encrypted is not None
        if not row.revocation_pending:
            self.clear_tokens(row)

    @asynccontextmanager
    async def locked(self, *, digest: str | None = None, session_id: UUID | None = None,
                     user_id: UUID | None = None) -> AsyncIterator[tuple[AsyncSession, BrowserSession | None]]:
        if (digest is None) == (session_id is None):
            raise ValueError("Select a session by digest or session ID")
        query = select(BrowserSession).where(
            BrowserSession.cookie_digest == digest if digest is not None else BrowserSession.session_id == session_id,
        )
        if user_id is not None:
            query = query.where(BrowserSession.user_id == user_id)
        async with self.db.transaction() as session:
            row = await session.scalar(query.with_for_update())
            yield session, row

    async def create(self, row: BrowserSession, *, previous_digest: str | None = None) -> None:
        async with self.db.transaction() as session:
            if previous_digest is not None:
                previous = await session.scalar(select(BrowserSession).where(
                    BrowserSession.cookie_digest == previous_digest,
                ).with_for_update())
                if previous is not None:
                    self.revoke(session, previous, "replaced")
            session.add(row)
            await session.flush()
            self.event(session, row, SessionEventType.CREATED)

    async def list(self, user_id: UUID, *, limit: int = 50, offset: int = 0) -> list[BrowserSession]:
        async with self.db.session() as session:
            return list(await session.scalars(select(BrowserSession).where(
                BrowserSession.user_id == user_id,
            ).order_by(BrowserSession.created_at.desc(), BrowserSession.session_id).limit(limit).offset(offset)))

    async def revoke_user(self, user_id: UUID, *, reason: str, pending: bool) -> None:
        async with self.db.transaction() as session:
            rows = await session.scalars(select(BrowserSession).where(
                BrowserSession.user_id == user_id,
            ).order_by(BrowserSession.session_id).with_for_update())
            for row in rows:
                self.revoke(session, row, reason, pending=pending)

    async def cleanup_candidates(self, *, idle_seconds: int, limit: int = 100) -> list[UUID]:
        now = utcnow()
        async with self.db.session() as session:
            return list(await session.scalars(select(BrowserSession.session_id).where(or_(
                BrowserSession.revocation_pending.is_(True),
                (BrowserSession.revoked_at.is_(None)) & or_(
                    BrowserSession.expires_at <= now,
                    BrowserSession.last_used_at <= now - timedelta(seconds=idle_seconds),
                ),
            )).order_by(BrowserSession.last_used_at, BrowserSession.session_id).limit(limit)))

    async def purge(self, retention_seconds: int) -> None:
        async with self.db.transaction() as session:
            await session.execute(delete(BrowserSession).where(
                BrowserSession.revoked_at < utcnow() - timedelta(seconds=retention_seconds),
                BrowserSession.revocation_pending.is_(False),
            ))
