import json
import redis
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

DEFAULT_CACHE_EXPIRE_TIME = 60 * 60 * 12

Metadata = Dict[str, Any]


class MetadataPlugin(ABC):
    __depends_on__: List[str] = []
    __cacheable__: bool = False
    __cache_expire_time__: int = DEFAULT_CACHE_EXPIRE_TIME

    def __init__(self) -> None:
        self.redis: Optional[redis.StrictRedis] = None

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def set_redis(self, redis: redis.StrictRedis) -> None:
        self.redis = redis

    def __rs_key(self, cache_tag: str) -> str:
        return f"cached:{self.name}:{cache_tag}"

    def _cache_fetch(self, cache_tag: str) -> Metadata:
        if not self.redis:
            return {}
        rs_key = self.__rs_key(cache_tag)
        obj = self.redis.get(rs_key)

        if obj:
            self.redis.expire(rs_key, self.__cache_expire_time__)
            return json.loads(obj)
        return {}

    def _cache_store(self, cache_tag: str, obj: Metadata) -> None:
        if not self.redis:
            return
        rs_key = self.__rs_key(cache_tag)
        self.redis.setex(rs_key, self.__cache_expire_time__, json.dumps(obj))

    def identify(self, matched_fname: str) -> Optional[str]:
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
        raise NotImplementedError
