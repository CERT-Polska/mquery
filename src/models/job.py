from sqlmodel import Field, SQLModel
from typing import Union, Optional, List


class Job(SQLModel):
    id: Union[int, None] = Field(default=None, primary_key=True)
    status: str
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
    # taints: List[str]
    datasets_left: int
    total_datasets: int
    agents_left: int
