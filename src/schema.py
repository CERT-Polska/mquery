from enum import Enum
from typing import List, Dict, Optional
from datetime import datetime
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
    total_files: int
    iterator: Optional[str]
    taint: Optional[str]


class JobsSchema(BaseModel):
    jobs: List[JobSchema]


class StorageSchema(BaseModel):
    id: str
    name: str
    path: str
    indexing_job_id: Optional[str]
    last_update: datetime
    taints: List[str]
    enabled: bool


class StorageCreateRequestSchema(BaseModel):
    name: str
    path: str


class StorageRequestSchema(BaseModel):
    id: str


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


class BackendStatusSchema(BaseModel):
    db_alive: bool
    tasks: List[TaskSchema]
    components: Dict


class BackendStatusDatasetsSchema(BaseModel):
    db_alive: bool
    datasets: Dict
