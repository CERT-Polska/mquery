from enum import Enum
from typing import List, Dict, Optional
from typing_extensions import TypedDict

from pydantic import BaseModel


class JobSchema(BaseModel):
    status: str
    rule_name: str
    rule_author: str
    raw_yara: str
    submitted: int
    priority: str


class TaskSchema(BaseModel):
    connection_id: str
    epoch_ms: int
    id: str
    request: str
    work_done: int
    work_estimated: int


class RequestQueryMethod(str, Enum):
    parse = "parse"


class QueryRequestSchema(BaseModel):
    raw_yara: str
    taint: str
    priority: str
    method: Optional[RequestQueryMethod]


class QueryResponseSchema(BaseModel):
    query_hash: str


class ParseQuerySchema(BaseModel):
    rule_name: str
    rule_author: str
    is_global: bool
    is_private: bool
    parsed: str


class DownloadSchema(BaseModel):
    job_id: str
    file_path: str
    ordinal: int


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


class BackendStatusSchema(BaseModel):
    db_alive: bool
    tasks: List[TaskSchema]
    components: TypedDict("components", {"mquery": str, "ursadb": str})


class BackendStatusDatasetsSchema(BaseModel):
    db_alive: bool
    datasets: TypedDict("datasets", {"indexes": List[TypedDict("index", {"type": str})]})
