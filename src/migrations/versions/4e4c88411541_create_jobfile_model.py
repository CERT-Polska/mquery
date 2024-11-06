"""create Jobfile model
Revision ID: 4e4c88411541
Revises: dbb81bd4d47f
Create Date: 2024-10-17 14:31:49.278443
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "4e4c88411541"
down_revision = "dbb81bd4d47f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "jobfile",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("files", sa.ARRAY(sa.String()), nullable=True),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["job.internal_id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("jobfile")
