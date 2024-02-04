from sqlmodel import SQLModel, Field, ARRAY, String, Column
from typing import Optional, List, Union


class Job(SQLModel, table=True):
    internal_id: Union[int, None] = Field(default=None, primary_key=True)
    id: Union[str, None]
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
    taints: List[str] = Field(sa_column=Column(ARRAY(String)))
    datasets_left: int
    total_datasets: int
    agents_left: int
