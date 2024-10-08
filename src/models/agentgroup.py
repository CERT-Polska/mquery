from sqlmodel import SQLModel, Field, Column, ARRAY, String, JSON, Relationship
from typing import Union, List, Dict
from ..models.jobagent import JobAgent


class AgentGroupView(SQLModel):
    name: str
    ursadb_url: str
    plugins_spec: Dict[str, Dict[str, str]] = Field(sa_column=Column(JSON))
    active_plugins: List[str] = Field(sa_column=Column(ARRAY(String)))


class AgentGroup(AgentGroupView, table=True):
    """Agent group is a group of processes working on a single
    file group, with a shared storage, and a single backing ursadb.
    """

    id: Union[int, None] = Field(default=None, primary_key=True)
    jobs: List["JobAgent"] = Relationship(back_populates="agent")
