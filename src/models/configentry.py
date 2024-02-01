from sqlmodel import Field, SQLModel
from typing import Union


class ConfigEntry(SQLModel, table=True):
    id: Union[int, None] = Field(default=None, primary_key=True)
    plugin: str
    key: str
    value: str
