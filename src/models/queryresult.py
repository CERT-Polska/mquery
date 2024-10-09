from sqlmodel import Field, SQLModel, ARRAY, Column, String
from typing import List


class QueryResult(SQLModel, table=True):
  job_id: str = Field(foreign_key="job.internal_id", primary_key=True)
  files: List[str] = Field(sa_column=Column(ARRAY(String)))
