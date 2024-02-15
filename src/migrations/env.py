from sqlalchemy import create_engine
from alembic import context
from sqlmodel import SQLModel

from mquery.config import app_config
from mquery.models.agentgroup import AgentGroup
from mquery.models.configentry import ConfigEntry
from mquery.models.job import Job
from mquery.models.match import Match


target_metadata = SQLModel.metadata


def run_migrations_online() -> None:
    connectable = create_engine(app_config.database.url)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
