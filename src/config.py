from typedconfig import Config, key, section, group_key  # type: ignore
from typedconfig.source import EnvironmentConfigSource, IniFileConfigSource  # type: ignore
import os


@section("redis")
class RedisConfig(Config):
    # Hostname of a configured redis instance.
    host = key(cast=str, required=False, default="localhost")
    # Port of a configured redis instance.
    port = key(cast=int, required=False, default=6379)


@section("rq")
class RqConfig(Config):
    # Maximum timeout value for tasks (in seconds)
    timeout = key(cast=int, required=False, default=180)


@section("mquery")
class MqueryConfig(Config):
    # URL to a UrsaDB instance.
    backend = key(cast=str, required=False, default="tcp://127.0.0.1:9281")
    # List of plugin specifications separated by comma, for example
    # "plugins.archive:GzipPlugin, plugins.custom:CustomPlugin"
    plugins = key(cast=str, required=False, default="")
    # Maximum number of yara-scanned files per query (0 means no limit).
    yara_limit = key(cast=int, required=False, default=0)
    # Html code to be displayed on the about page.
    about = key(cast=str, required=False, default="")


class AppConfig(Config):
    redis = group_key(RedisConfig)
    rq = group_key(RqConfig)
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
