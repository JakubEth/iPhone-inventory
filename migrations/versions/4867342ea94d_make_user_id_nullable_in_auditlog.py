"""Make user_id nullable in AuditLog

Revision ID: 4867342ea94d
Revises: f156c7451ee0
Create Date: 2024-12-10 23:51:07.526047

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4867342ea94d'
down_revision: Union[str, None] = 'f156c7451ee0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create a new table with the desired schema
    op.create_table(
        'audit_logs_new',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action', sa.String(255), nullable=False),
        sa.Column('timestamp', sa.DateTime, nullable=False),
        sa.Column('details', sa.Text, nullable=True)
    )

    # Copy data from the old table to the new table
    op.execute('''
        INSERT INTO audit_logs_new (id, user_id, action, timestamp, details)
        SELECT id, user_id, action, timestamp, details FROM audit_logs
    ''')

    # Drop the old table
    op.drop_table('audit_logs')

    # Rename the new table to the original table name
    op.rename_table('audit_logs_new', 'audit_logs')


def downgrade() -> None:
    # Reverse the upgrade steps
    op.create_table(
        'audit_logs_old',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=False),
        sa.Column('action', sa.String(255), nullable=False),
        sa.Column('timestamp', sa.DateTime, nullable=False),
        sa.Column('details', sa.Text, nullable=True)
    )

    op.execute('''
        INSERT INTO audit_logs_old (id, user_id, action, timestamp, details)
        SELECT id, user_id, action, timestamp, details FROM audit_logs
    ''')

    op.drop_table('audit_logs')

    op.rename_table('audit_logs_old', 'audit_logs')
