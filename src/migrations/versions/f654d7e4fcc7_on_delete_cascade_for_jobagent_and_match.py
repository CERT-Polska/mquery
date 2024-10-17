"""on delete cascade for jobagent and match
Revision ID: f654d7e4fcc7
Revises: 6b495d5a4855
Create Date: 2024-10-17 07:16:34.262079
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "f654d7e4fcc7"
down_revision = "6b495d5a4855"
branch_labels = None
depends_on = None


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


def downgrade() -> None:
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
