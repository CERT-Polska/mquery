from pydantic import validator
from sqlmodel import Field, SQLModel
from typing import Union


class ConfigEntryBase(SQLModel):
    plugin: str
    key: str
    value: str


class ConfigEntry(ConfigEntryBase, table=True):
    id: Union[int, None] = Field(default=None, primary_key=None)

