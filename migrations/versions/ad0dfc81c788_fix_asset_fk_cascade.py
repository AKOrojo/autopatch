"""fix_asset_fk_cascade

Revision ID: ad0dfc81c788
Revises: 3a96258d090b
Create Date: 2026-04-13 19:29:29.517750

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'ad0dfc81c788'
down_revision: Union[str, Sequence[str], None] = '3a96258d090b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # scans: cascade delete when asset is removed
    op.drop_constraint('scans_asset_id_fkey', 'scans', type_='foreignkey')
    op.create_foreign_key('scans_asset_id_fkey', 'scans', 'assets', ['asset_id'], ['id'], ondelete='CASCADE')

    # vulnerabilities: cascade delete when asset is removed
    op.drop_constraint('vulnerabilities_asset_id_fkey', 'vulnerabilities', type_='foreignkey')
    op.create_foreign_key('vulnerabilities_asset_id_fkey', 'vulnerabilities', 'assets', ['asset_id'], ['id'], ondelete='CASCADE')

    # scan_reports: cascade delete when asset is removed
    op.drop_constraint('scan_reports_asset_id_fkey', 'scan_reports', type_='foreignkey')
    op.create_foreign_key('scan_reports_asset_id_fkey', 'scan_reports', 'assets', ['asset_id'], ['id'], ondelete='CASCADE')

    # audit_log: set null (preserve history, just lose the link)
    op.drop_constraint('audit_log_asset_id_fkey', 'audit_log', type_='foreignkey')
    op.create_foreign_key('audit_log_asset_id_fkey', 'audit_log', 'assets', ['asset_id'], ['id'], ondelete='SET NULL')

    # approval_requests: set null (preserve approval history)
    op.drop_constraint('approval_requests_asset_id_fkey', 'approval_requests', type_='foreignkey')
    op.create_foreign_key('approval_requests_asset_id_fkey', 'approval_requests', 'assets', ['asset_id'], ['id'], ondelete='SET NULL')


def downgrade() -> None:
    op.drop_constraint('scans_asset_id_fkey', 'scans', type_='foreignkey')
    op.create_foreign_key('scans_asset_id_fkey', 'scans', 'assets', ['asset_id'], ['id'])

    op.drop_constraint('vulnerabilities_asset_id_fkey', 'vulnerabilities', type_='foreignkey')
    op.create_foreign_key('vulnerabilities_asset_id_fkey', 'vulnerabilities', 'assets', ['asset_id'], ['id'])

    op.drop_constraint('scan_reports_asset_id_fkey', 'scan_reports', type_='foreignkey')
    op.create_foreign_key('scan_reports_asset_id_fkey', 'scan_reports', 'assets', ['asset_id'], ['id'])

    op.drop_constraint('audit_log_asset_id_fkey', 'audit_log', type_='foreignkey')
    op.create_foreign_key('audit_log_asset_id_fkey', 'audit_log', 'assets', ['asset_id'], ['id'])

    op.drop_constraint('approval_requests_asset_id_fkey', 'approval_requests', type_='foreignkey')
    op.create_foreign_key('approval_requests_asset_id_fkey', 'approval_requests', 'assets', ['asset_id'], ['id'])
