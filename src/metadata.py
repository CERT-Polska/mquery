import json
from abc import ABC, abstractmethod
from typing import List

DEFAULT_CACHE_EXPIRE_TIME = 60 * 60 * 12


class MetadataPlugin(ABC):
    __depends_on__: List[str] = []
    __cacheable__: bool = False
    __cache_expire_time__: int = DEFAULT_CACHE_EXPIRE_TIME

    def __init__(self):
        self.redis = None

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def set_redis(self, redis):
        self.redis = redis

    def __rs_key(self, cache_tag):
        cls_name = self.__class__.__name__
        rs_key = "cached:{}:{}".format(cls_name, cache_tag)
        return rs_key

    def _cache_fetch(self, cache_tag):
        rs_key = self.__rs_key(cache_tag)
        obj = self.redis.get(rs_key)

        if obj:
            self.redis.expire(rs_key, self.__cache_expire_time__)
            return json.loads(obj)

    def _cache_store(self, cache_tag, obj):
        rs_key = self.__rs_key(cache_tag)
        self.redis.setex(rs_key, self.__cache_expire_time__, json.dumps(obj))

    def identify(self, matched_fname):
        return matched_fname

    def run(self, matched_fname, current_meta):
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
    def extract(self, identifier, matched_fname, current_meta):
        raise NotImplementedError
