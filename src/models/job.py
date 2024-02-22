from sqlmodel import SQLModel, Field, ARRAY, String, Column, Relationship
from typing import Optional, List, Union, TYPE_CHECKING
from enum import Enum


if TYPE_CHECKING:
    from ..models.match import Match
    from ..models.agentjob import AgentJob


class JobStatus(Enum):
    new = "new"  # Completely new job.
    inprogress = "inprogress"  # Job that is in progress.
    done = "done"  # Job that was finished
    cancelled = "cancelled"  # Job was cancelled by the user or failed


class JobBase(SQLModel):
    """Base class for entities related to mquery jobs.
    
    A job has one or more agentjobs assigned. Most of the actual job status
    information is stored in agents.
    """

    id: str
    error: Optional[str]
    rule_name: str
    rule_author: str
    raw_yara: str
    submitted: int
    finished: Optional[int]
    files_limit: int
    reference: str
    taints: List[str] = Field(sa_column=Column(ARRAY(String)))

    agentjobs: List["AgentJob"] = Relationship(back_populates="job")

    @property
    def files_processed(self) -> int:
        """Sum of files_processed for all agentjobs."""
        return sum(a.files_processed for a in self.agentjobs)

    @property
    def files_matched(self) -> int:
        """Sum of files_matched for all agentjobs."""
        return sum(a.files_matched for a in self.agentjobs)

    @property
    def files_in_progress(self) -> int:
        """Sum of files_in_progress for all agentjobs."""
        return sum(a.files_in_progress for a in self.agentjobs)

    @property
    def files_errored(self) -> int:
        """Sum of files_errored for all agentjobs."""
        return sum(a.files_errored for a in self.agentjobs)

    @property
    def total_files(self) -> int:
        """Sum of total_files for all agentjobs."""
        return sum(a.total_files for a in self.agentjobs)

    @property
    def datasets_left(self) -> int:
        """Sum of datasets_left for all agentjobs."""
        return sum(a.datasets_left for a in self.agentjobs)

    @property
    def total_datasets(self) -> int:
        """Sum of total_datasets for all agentjobs."""
        return sum(a.total_datasets for a in self.agentjobs)

    @property
    def agents_left(self) -> int:
        """How many agents are still processing the job."""
        return len([a for a in self.agentjobs if not a.completed])

    @property
    def status(self) -> JobStatus:
        """What is the current job status (based on agentjob statuses)."""
        if self.error:
            return JobStatus.cancelled  # This includes manually cancelled jobs.

        for agentjob in self.agentjobs:
            if not agentjob.completed:
                # At least one agent is still processing the job.
                return JobStatus.inprogress
        
        if self.finished is None:
            return JobStatus.new  # Special case - job not even started.

        return JobStatus.done


class Job(JobBase, table=True):
    """Job object in the database. Internal ID is an implementation detail."""

    internal_id: Union[int, None] = Field(default=None, primary_key=True)

    matches: List["Match"] = Relationship(back_populates="job")


class JobView(JobBase):
    """Pydantic model used in the public API."""

    pass
