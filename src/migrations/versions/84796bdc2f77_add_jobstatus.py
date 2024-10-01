"""add_jobstatus
Revision ID: 84796bdc2f77
Revises: dbb81bd4d47f
Create Date: 2024-10-01 08:09:42.808911
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "84796bdc2f77"
down_revision = "dbb81bd4d47f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE TYPE jobstatus AS ENUM ('done', 'new', 'cancelled', 'removed', 'processing');"
    )
    op.execute(
        "ALTER TABLE job ALTER COLUMN status TYPE jobstatus USING status::text::jobstatus;"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE job ALTER COLUMN status TYPE VARCHAR USING status::text;"
    )
