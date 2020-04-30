import json
from abc import ABC, abstractmethod
from db import Database
from typing import Any, Dict, List, Optional

DEFAULT_CACHE_EXPIRE_TIME = 60 * 60 * 12

Metadata = Dict[str, Any]
MetadataPluginConfig = Dict[str, str]


class MetadataPlugin(ABC):
    #: Enables cache for extracted metadata
    __cacheable__: bool = False
    #: Overrides default cache expire time
    __cache_expire_time__: int = DEFAULT_CACHE_EXPIRE_TIME
    #: Configuration keys required by plugin with description as a value
    __config_fields__: Dict[str, str] = {}

    def __init__(self, db: Database, config: MetadataPluginConfig) -> None:
        self.db = db
        for key in self.__config_fields__.keys():
            if key not in config or not config[key]:
                raise KeyError(
                    f"Required configuration key '{key}' is not set"
                )

    @classmethod
    def get_name(cls) -> str:
        return cls.__name__

    def __cache_key(self, cache_tag: str) -> str:
        return f"{self.get_name()}:{cache_tag}"

    def _cache_fetch(self, cache_tag: str) -> Metadata:
        obj = self.db.cache_get(
            self.__cache_key(cache_tag), expire=self.__cache_expire_time__
        )

        if obj:
            return json.loads(obj)
        return {}

    def _cache_store(self, cache_tag: str, obj: Metadata) -> None:
        self.db.cache_store(
            self.__cache_key(cache_tag),
            json.dumps(obj),
            expire=self.__cache_expire_time__,
        )

    def identify(self, matched_fname: str) -> Optional[str]:
        """
        Returns file unique identifier based on matched path.

        Intended to be overridden by plugin.
       """
        return matched_fname

    def run(self, matched_fname: str, current_meta: Metadata) -> Metadata:
        identifier = self.identify(matched_fname)
        if identifier is None:
            return {}
        # If plugin allows to cache data: try to fetch from cache
        if self.__cacheable__:
            cached = self._cache_fetch(identifier)
            if cached:
                return cached
        # Extract data
        result = self.extract(identifier, matched_fname, current_meta)

        if self.__cacheable__:
            self._cache_store(identifier, result)
        return result

    @abstractmethod
    def extract(
        self, identifier: str, matched_fname: str, current_meta: Metadata
    ) -> Metadata:
        """
        Extracts metadata for matched path

        Intended to be overridden by plugin.

        :param identifier: File identifier returned by overridable
                           :py:meth:`MetadataPlugin.identify` method
        :param matched_fname: Matched file path
        :param current_meta: Metadata extracted so far by dependencies
        :return: Metadata object. If you can't extract metadata for current file,
                 return empty dict.
       """
        raise NotImplementedError
