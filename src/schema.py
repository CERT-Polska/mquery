from enum import Enum
from typing import List, Dict, Optional, Sequence
from pydantic import BaseModel, Field  # type: ignore
from .models.job import JobView
from .models.agentgroup import AgentGroupView


class JobsSchema(BaseModel):
    jobs: Sequence[JobView]


class ConfigSchema(BaseModel):
    plugin: str
    key: str
    value: str
    description: str


class TaskSchema(BaseModel):
    connection_id: str
    epoch_ms: int
    id: str
    request: str
    work_done: int
    work_estimated: int


class RequestQueryMethod(str, Enum):
    query = "query"
    parse = "parse"


class RequestConfigEdit(BaseModel):
    plugin: str
    key: str
    value: str


class QueryRequestSchema(BaseModel):
    raw_yara: str
    taints: Optional[List[str]]
    method: str
    files_limit: Optional[int]
    reference: Optional[str]  # arbitrary data specified by the user
    required_plugins: List[str] = Field([])
    force_slow_queries: bool = False


class QueryResponseSchema(BaseModel):
    query_hash: str


class ParseResponseSchema(BaseModel):
    rule_name: str
    rule_author: str
    is_global: bool
    is_private: bool
    is_degenerate: bool
    parsed: str


class MatchesSchema(BaseModel):
    job: JobView
    matches: List[Dict]


class StatusSchema(BaseModel):
    status: str


class UserSettingsSchema(BaseModel):
    can_register: bool
    plugin_name: str


class UserInfoSchema(BaseModel):
    id: int
    name: str


class UserAuthSchema(BaseModel):
    username: str
    password: str


class AgentSchema(BaseModel):
    name: str
    alive: bool
    tasks: List
    spec: AgentGroupView


class BackendStatusSchema(BaseModel):
    agents: List[AgentSchema]
    components: Dict[str, str]


class BackendStatusDatasetsSchema(BaseModel):
    datasets: Dict


class ServerSchema(BaseModel):
    version: str
    auth_enabled: Optional[str]
    openid_url: Optional[str]
    openid_client_id: Optional[str]
    about: str
