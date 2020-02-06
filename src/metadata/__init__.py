import json

CACHE_EXPIRE_TIME = 60*60*12


class Metadata:
    def __init__(self):
        self.redis = None

    def set_redis(self, redis):
        self.redis = redis

    def __rs_key(self, cache_tag):
        cls_name = self.__class__.__name__
        rs_key = 'cached:{}:{}'.format(cls_name, cache_tag)
        return rs_key

    def cache_fetch(self, cache_tag):
        rs_key = self.__rs_key(cache_tag)
        obj = self.redis.get(rs_key)

        if obj:
            self.redis.expire(rs_key, CACHE_EXPIRE_TIME)
            return json.loads(obj)

    def cache_store(self, cache_tag, obj):
        rs_key = self.__rs_key(cache_tag)
        self.redis.setex(rs_key, CACHE_EXPIRE_TIME, json.dumps(obj))
