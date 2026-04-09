"""add tier column to assets

Revision ID: 428abbd049ac
Revises: 547acffb1125
Create Date: 2026-04-09 21:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '428abbd049ac'
down_revision: Union[str, Sequence[str], None] = '547acffb1125'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add as nullable first, backfill existing rows, then set NOT NULL
    op.add_column('assets', sa.Column('tier', sa.String(length=20), nullable=True))
    op.execute("UPDATE assets SET tier = 'dev' WHERE tier IS NULL")
    op.alter_column('assets', 'tier', nullable=False, server_default='dev')


def downgrade() -> None:
    op.drop_column('assets', 'tier')
