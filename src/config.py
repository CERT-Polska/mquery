from typedconfig import Config, key, section, group_key  # type: ignore
from typedconfig.source import EnvironmentConfigSource, IniFileConfigSource  # type: ignore
import os


@section("redis")
class RedisConfig(Config):
    host = key(cast=str, required=False, default="localhost")
    port = key(cast=int, required=False, default=6379)


@section("mquery")
class MqueryConfig(Config):
    backend = key(cast=str, required=False, default="tcp://127.0.0.1:9281")
    plugins = key(cast=str, required=False, default="")


class AppConfig(Config):
    redis = group_key(RedisConfig)
    mquery = group_key(MqueryConfig)


def _config_sources():
    return [
        EnvironmentConfigSource(),
        IniFileConfigSource("mquery.ini", must_exist=False),
        IniFileConfigSource(
            os.path.expanduser("~/.config/mquery/mquery.ini"), must_exist=False
        ),
        IniFileConfigSource("/etc/mquery/mquery.ini", must_exist=False),
    ]


app_config = AppConfig(sources=_config_sources())
