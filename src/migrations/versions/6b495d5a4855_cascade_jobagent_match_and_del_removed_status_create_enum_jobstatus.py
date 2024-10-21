"""add jobstatus
Revision ID: 6b495d5a4855
Revises: dbb81bd4d47f
Create Date: 2024-10-15 08:17:30.036531
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "6b495d5a4855"
down_revision = "dbb81bd4d47f"
branch_labels = None
depends_on = None

job_status = sa.Enum(
    "done", "new", "cancelled", "processing", name="jobstatus"
)


def upgrade() -> None:
    op.drop_constraint("jobagent_job_id_fkey", "jobagent", type_="foreignkey")
    op.create_foreign_key(
        constraint_name="jobagent_job_id_fkey",
        source_table="jobagent",
        referent_table="job",
        local_cols=["job_id"],
        remote_cols=["internal_id"],
        ondelete="CASCADE",
    )

    op.drop_constraint("match_job_id_fkey", "match", type_="foreignkey")
    op.create_foreign_key(
        constraint_name="match_job_id_fkey",
        source_table="match",
        referent_table="job",
        local_cols=["job_id"],
        remote_cols=["internal_id"],
        ondelete="CASCADE",
    )

    op.execute("DELETE FROM job WHERE status = 'removed';")

    job_status.create(op.get_bind())
    op.alter_column(
        "job",
        "status",
        existing_type=sa.VARCHAR(),
        type_=job_status,
        postgresql_using="status::jobstatus",
        nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "job",
        "status",
        existing_type=job_status,
        type_=sa.VARCHAR(),
        nullable=False,
    )

    op.execute("DROP TYPE IF EXISTS jobstatus")

    op.drop_constraint("jobagent_job_id_fkey", "jobagent", type_="foreignkey")
    op.create_foreign_key(
        constraint_name="jobagent_job_id_fkey",
        source_table="jobagent",
        referent_table="job",
        local_cols=["job_id"],
        remote_cols=["internal_id"],
    )

    op.drop_constraint("match_job_id_fkey", "match", type_="foreignkey")
    op.create_foreign_key(
        constraint_name="match_job_id_fkey",
        source_table="match",
        referent_table="job",
        local_cols=["job_id"],
        remote_cols=["internal_id"],
    )
