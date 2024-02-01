from typing import Iterator

from sqlmodel import Session, SQLModel, create_engine

from .config import app_config


engine = create_engine(app_config.database, echo=False)


def init_schema() -> None:
    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
