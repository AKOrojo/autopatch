"""add progress to scans

Revision ID: b1c2d3e4f5a6
Revises: ad0dfc81c788
Create Date: 2026-04-13 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b1c2d3e4f5a6'
down_revision: Union[str, Sequence[str], None] = 'ad0dfc81c788'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('progress', sa.Integer(), nullable=False, server_default='0'))


def downgrade() -> None:
    op.drop_column('scans', 'progress')
