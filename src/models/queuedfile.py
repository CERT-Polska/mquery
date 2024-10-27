from sqlmodel import SQLModel, Field
from typing import Union


class QueuedFile(SQLModel, table=True):
    """Represents a file queued to be indexed."""

    id: Union[int, None] = Field(default=None, primary_key=True)

    # ID of the ursadb ("agent group") this file belongs to.
    ursadb_id: str

    # A file path on one of the daemons
    path: str
