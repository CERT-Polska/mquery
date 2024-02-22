from sqlmodel import SQLModel, Field, ARRAY, String, Column, Relationship
from typing import Optional, List, Union, TYPE_CHECKING

from ..models.job import Job


class AgentJob(SQLModel, table=True):
    """A piece of work assigned to a single agent."""

    id: Union[int, None] = Field(default=None, primary_key=True)
    # Reference to the related job ID.
    job_id: int
    # How many files were processed (out of total_files).
    files_in_progress: int
    # How many of files_processed threw an error.
    files_processed: int
    # How many of files_processed matched the rule.
    files_matched: int
    # How many files are currently being processed.
    files_errored: int
    # How many files are were matched by ursadb.
    total_files: int
    # How many datasets are left to query.
    datasets_left: int
    # How many datasets were selected for the query.
    total_datasets: int

    job: Job = Relationship(back_populates="agentjobs")

    def completed(self) -> bool:
        """Did this agent finish all its tasks."""
        return self.datasets_left == 0 and self.files_processed >= self.total_files
