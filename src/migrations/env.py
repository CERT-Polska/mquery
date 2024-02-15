from sqlalchemy import create_engine
from alembic import context
from sqlmodel import SQLModel

from mquery.config import app_config
from mquery.models.agentgroup import AgentGroup  # noqa type: ignore
from mquery.models.configentry import ConfigEntry  # noqa type: ignore
from mquery.models.job import Job  # noqa type: ignore
from mquery.models.match import Match  # noqa type: ignore


target_metadata = SQLModel.metadata


def run_migrations_online() -> None:
    connectable = create_engine(app_config.database.url)
    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
