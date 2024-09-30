from sqlmodel import SQLModel, Field, ARRAY, String, Column, JSON, Relationship
from typing import List, Union, Dict, Any

from ..models.job import Job


class Match(SQLModel, table=True):  # type: ignore
    """Represents a file matched to a job, along with a related metadata."""

    id: Union[int, None] = Field(default=None, primary_key=True)
    # A file path on one of the daemons
    file: str
    # A metadata dictionary - contains various tags added by plugins
    meta: Dict[str, Any] = Field(sa_column=Column(JSON))
    # A list of yara rules matched to this file
    matches: List[str] = Field(sa_column=Column(ARRAY(String)))

    job_id: int = Field(foreign_key="job.internal_id")
    job: Job = Relationship(back_populates="matches")
