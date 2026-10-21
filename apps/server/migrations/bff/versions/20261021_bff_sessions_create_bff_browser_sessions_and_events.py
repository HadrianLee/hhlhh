"""create BFF browser sessions and events

Revision ID: 20261021_bff_sessions
Revises: 
Create Date: 2026-10-21 19:36:26.433461
"""

from alembic import op
import sqlalchemy as sa


revision = '20261021_bff_sessions'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('browser_sessions',
    sa.Column('session_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('identity_session_id', sa.Uuid(), nullable=False),
    sa.Column('cookie_digest', sa.String(length=64), nullable=False),
    sa.Column('access_token_encrypted', sa.LargeBinary(), nullable=True),
    sa.Column('refresh_token_encrypted', sa.LargeBinary(), nullable=True),
    sa.Column('access_expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('refresh_expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoke_reason', sa.String(length=64), nullable=True),
    sa.Column('revocation_pending', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('ip_address', sa.String(length=45), nullable=True),
    sa.Column('user_agent', sa.String(length=512), nullable=True),
    sa.CheckConstraint('(access_token_encrypted IS NULL) = (refresh_token_encrypted IS NULL)', name=op.f('ck_browser_sessions_token_pair')),
    sa.CheckConstraint('NOT revocation_pending OR revoked_at IS NOT NULL', name=op.f('ck_browser_sessions_pending_is_revoked')),
    sa.CheckConstraint('expires_at > created_at', name=op.f('ck_browser_sessions_expiry_after_creation')),
    sa.CheckConstraint('last_used_at >= created_at', name=op.f('ck_browser_sessions_last_used_after_creation')),
    sa.CheckConstraint('length(cookie_digest) = 64', name=op.f('ck_browser_sessions_cookie_digest_length')),
    sa.CheckConstraint('revoked_at IS NOT NULL OR access_token_encrypted IS NOT NULL', name=op.f('ck_browser_sessions_active_tokens_present')),
    sa.PrimaryKeyConstraint('session_id', name=op.f('pk_browser_sessions')),
    sa.UniqueConstraint('cookie_digest', name=op.f('uq_browser_sessions_cookie_digest')),
    sa.UniqueConstraint('identity_session_id', name=op.f('uq_browser_sessions_identity_session_id')),
    schema='bff'
    )
    op.create_index('ix_browser_sessions_cleanup', 'browser_sessions', ['revocation_pending', 'last_used_at'], unique=False, schema='bff')
    op.create_index('ix_browser_sessions_user_active', 'browser_sessions', ['user_id', 'revoked_at', 'expires_at'], unique=False, schema='bff')
    op.create_table('session_events',
    sa.Column('event_id', sa.Uuid(), nullable=False),
    sa.Column('session_id', sa.Uuid(), nullable=False),
    sa.Column('event_type', sa.String(length=32), nullable=False),
    sa.Column('reason', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("event_type IN ('created', 'refreshed', 'revoked', 'identity_revoked')", name=op.f('ck_session_events_event_type_allowed')),
    sa.ForeignKeyConstraint(['session_id'], ['bff.browser_sessions.session_id'], name=op.f('fk_session_events_session_id_browser_sessions'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('event_id', name=op.f('pk_session_events')),
    schema='bff'
    )
    op.create_index('ix_session_events_session_created', 'session_events', ['session_id', 'created_at'], unique=False, schema='bff')


def downgrade() -> None:
    op.drop_index('ix_session_events_session_created', table_name='session_events', schema='bff')
    op.drop_table('session_events', schema='bff')
    op.drop_index('ix_browser_sessions_user_active', table_name='browser_sessions', schema='bff')
    op.drop_index('ix_browser_sessions_cleanup', table_name='browser_sessions', schema='bff')
    op.drop_table('browser_sessions', schema='bff')
