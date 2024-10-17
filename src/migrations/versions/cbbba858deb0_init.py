"""Init
Revision ID: cbbba858deb0
Revises:
Create Date: 2024-02-15 16:52:45.261139.
"""
from alembic import op
import sqlalchemy as sa
import sqlmodel


revision = "cbbba858deb0"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agentgroup",
        sa.Column("plugins_spec", sa.JSON(), nullable=True),
        sa.Column("active_plugins", sa.ARRAY(sa.String()), nullable=True),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column(
            "ursadb_url", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("id", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "configentry",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "plugin", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("key", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("value", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "job",
        sa.Column("taints", sa.ARRAY(sa.String()), nullable=True),
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column(
            "status", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("error", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column(
            "rule_name", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column(
            "rule_author", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column(
            "raw_yara", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("submitted", sa.Integer(), nullable=False),
        sa.Column("finished", sa.Integer(), nullable=True),
        sa.Column("files_limit", sa.Integer(), nullable=False),
        sa.Column(
            "reference", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("files_processed", sa.Integer(), nullable=False),
        sa.Column("files_matched", sa.Integer(), nullable=False),
        sa.Column("files_in_progress", sa.Integer(), nullable=False),
        sa.Column("total_files", sa.Integer(), nullable=False),
        sa.Column("files_errored", sa.Integer(), nullable=False),
        sa.Column("datasets_left", sa.Integer(), nullable=False),
        sa.Column("total_datasets", sa.Integer(), nullable=False),
        sa.Column("agents_left", sa.Integer(), nullable=False),
        sa.Column("internal_id", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("internal_id"),
    )
    op.create_table(
        "match",
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("matches", sa.ARRAY(sa.String()), nullable=True),
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("file", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["job.internal_id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("match")
    op.drop_table("job")
    op.drop_table("configentry")
    op.drop_table("agentgroup")
