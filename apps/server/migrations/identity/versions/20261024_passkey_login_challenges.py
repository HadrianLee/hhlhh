"""Add browser-bound challenges for passkey sign-in.

Revision ID: 20261024_passkey_login
Revises: b5644db46545
"""
from alembic import op
import sqlalchemy as sa

revision = '20261024_passkey_login'
down_revision = 'b5644db46545'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('passkey_login_challenges',
        sa.Column('challenge_id', sa.Uuid(), nullable=False),
        sa.Column('challenge', sa.LargeBinary(), nullable=False),
        sa.Column('browser_binding', sa.String(64), nullable=False),
        sa.Column('rp_id', sa.String(253), nullable=False),
        sa.Column('origin', sa.String(2048), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('attempts_remaining', sa.Integer(), server_default='5', nullable=False),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.CheckConstraint('length(challenge) >= 16', name=op.f('ck_passkey_login_challenges_challenge_length')),
        sa.CheckConstraint('length(browser_binding) = 64', name=op.f('ck_passkey_login_challenges_binding_length')),
        sa.CheckConstraint('attempts_remaining BETWEEN 0 AND 5', name=op.f('ck_passkey_login_challenges_attempts_allowed')),
        sa.PrimaryKeyConstraint('challenge_id', name=op.f('pk_passkey_login_challenges')),
        schema='identity')
    op.create_index('ix_passkey_login_challenges_expires_at', 'passkey_login_challenges', ['expires_at'], schema='identity')


def downgrade() -> None:
    op.drop_index('ix_passkey_login_challenges_expires_at', table_name='passkey_login_challenges', schema='identity')
    op.drop_table('passkey_login_challenges', schema='identity')
