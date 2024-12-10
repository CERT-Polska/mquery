from sqlmodel import SQLModel, Field, ARRAY, String, Column
from typing import Union, List
from datetime import datetime


class QueuedFile(SQLModel, table=True):
    """Represents a file that is waiting to be indexed."""

    id: Union[int, None] = Field(default=None, primary_key=True)

    # ID of the ursadb ("agent group") this file belongs to.
    ursadb_id: str

    # A file path that should be indexed. This path should be
    # valid on the Ursadb with ID `ursadb_id` (or there should be a plugin
    # that knows how to process this path to get a valid file).
    path: str

    # Time when this file was added.
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
    )

    # Desired index types for this file (valid values include ["gram3",
    # "text4", "hash4" and "wide8"], database enum feels like an overkill).
    index_types: List[str] = Field(
        sa_column=Column(ARRAY(String), nullable=False)
    )

    # Desired tags for this file. Warning - overusing tags will have a big
    # negative impact on performance, it's best to keep to a few tags at most.
    tags: List[str] = Field(sa_column=Column(ARRAY(String), nullable=False))
