from sqlmodel import Field, SQLModel, ARRAY, Column, String
from typing import List, Union


class QueryResult(SQLModel, table=True):
    id: Union[int, None] = Field(default=None, primary_key=True)
    job_id: Union[int, None] = Field(foreign_key="job.internal_id")
    files: List[str] = Field(sa_column=Column(ARRAY(String)))
