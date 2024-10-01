import enum

from sqlalchemy import Enum as PgEnum
from sqlmodel import SQLModel, Field, ARRAY, String, Column, Relationship
from typing import Optional, List, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from ..models.match import Match
    from ..models.jobagent import JobAgent


class JobStatus(str, enum.Enum):
    done = "done"
    new = "new"
    cancelled = "cancelled"
    removed = "removed"
    processing = "processing"


class JobBase(SQLModel):
    """Base class for entities related to mquery jobs."""

    id: str
    status: JobStatus = Field(sa_type=PgEnum(JobStatus, name="jobstatus"))
    error: Optional[str]
    rule_name: str
    rule_author: str
    raw_yara: str
    submitted: int
    finished: Optional[int]
    files_limit: int
    reference: str
    files_processed: int
    files_matched: int
    files_in_progress: int
    total_files: int
    files_errored: int
    taints: List[str] = Field(sa_column=Column(ARRAY(String)))
    datasets_left: int
    total_datasets: int
    agents_left: int

    class Config:
        arbitrary_types_allowed = True


class Job(JobBase, table=True):
    """Job object in the database. Internal ID is an implementation detail."""

    internal_id: Union[int, None] = Field(default=None, primary_key=True)

    matches: List["Match"] = Relationship(back_populates="job")
    agents: List["JobAgent"] = Relationship(back_populates="job")


class JobView(JobBase):
    """Pydantic model used in the public API."""

    pass
