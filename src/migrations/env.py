from sqlalchemy import create_engine
from alembic import context
from sqlmodel import SQLModel
from logging.config import fileConfig

from mquery.config import app_config  # type: ignore
from mquery.models.agentgroup import AgentGroup  # type: ignore # noqa
from mquery.models.configentry import ConfigEntry  # type: ignore # noqa
from mquery.models.job import Job  # type: ignore # noqa
from mquery.models.match import Match  # type: ignore # noqa
from mquery.models.queuedfile import QueuedFile  # type: ignore # noqa


target_metadata = SQLModel.metadata


if context.config.config_file_name is not None:
    fileConfig(context.config.config_file_name)


def run_migrations_online() -> None:
    connectable = create_engine(app_config.database.url)
    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
