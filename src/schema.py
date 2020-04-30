from enum import Enum
from typing import List, Dict, Optional
from pydantic import BaseModel


class JobSchema(BaseModel):
    id: str
    status: str
    rule_name: str
    rule_author: Optional[str]
    raw_yara: str
    submitted: int
    priority: str
    files_processed: int
    files_matched: int
    files_in_progress: int
    total_files: int
    iterator: Optional[str]
    taint: Optional[str]


class JobsSchema(BaseModel):
    jobs: List[JobSchema]


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
    taint: Optional[str]
    priority: Optional[str]
    method: str


class QueryResponseSchema(BaseModel):
    query_hash: str


class ParseResponseSchema(BaseModel):
    rule_name: str
    rule_author: str
    is_global: bool
    is_private: bool
    parsed: str


class MatchesSchema(BaseModel):
    job: Dict
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


class AgentSpecSchema(BaseModel):
    ursadb_url: str
    plugins_spec: Dict[str, Dict[str, str]]
    active_plugins: List[str]


class AgentSchema(BaseModel):
    name: str
    alive: bool
    tasks: List
    spec: AgentSpecSchema


class BackendStatusSchema(BaseModel):
    agents: List[AgentSchema]
    components: Dict[str, str]


class BackendStatusDatasetsSchema(BaseModel):
    datasets: Dict
