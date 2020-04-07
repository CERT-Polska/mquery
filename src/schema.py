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


class RequestQueryMethod(str, Enum):
    parse = "parse"


class QuerySchema(BaseModel):
    query_hash: str


class ParseQuerySchema(BaseModel):
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


class BackendStatusSchema(BaseModel):
    db_alive: bool
    tasks: List[Dict[str, JobSchema]]
    components: TypedDict("components", {"mquery": str, "ursadb": str})


class BackendStatusDatasetsSchema(BaseModel):
    db_alive: bool
    datasets: List
