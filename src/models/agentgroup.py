from sqlmodel import SQLModel, Field, Column, ARRAY, String, JSON
from typing import Union, List, Dict


class AgentGroupBase(SQLModel):
    name: str
    ursadb_url: str
    plugins_spec: Dict[str, Dict[str, str]] = Field(sa_column=Column(JSON))
    active_plugins: List[str] = Field(sa_column=Column(ARRAY(String)))


class AgentGroup(AgentGroupBase, table=True):
    """Agent group is a group of processes working on a single
    file group, with a shared storage, and a single backing ursadb.
    """

    id: Union[int, None] = Field(default=None, primary_key=True)


class AgentGroupView(AgentGroupBase):
    """Pydantic model used in the public API."""

    pass
