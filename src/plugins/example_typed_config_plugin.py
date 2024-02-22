"""Plugin that serves as an example how to use existing typed-config
machinery to configure your own plugins.
"""

from typedconfig import Config, key, section

from ..db import Database
from ..metadata import Metadata, MetadataPlugin, MetadataPluginConfig
from ..config import app_config


@section("plugin.example")
class ExamplePluginConfig(Config):
    """Plugin configuration."""

    tag = key(cast=str)
    tag_url = key(cast=str)


# You will need to add this to your config file (or use env vars):
#
# [plugin.example]
# tag=kot
# tag_url=http://google.com


class ExamplePluginWithTypedConfig(MetadataPlugin):
    """This plugin serves as an example how to use typed-config and
    mquery config file to configure your own plugins. It's equivalent
    to ExamplePlugin in all except the configuration method.
    """

    is_extractor = True

    def __init__(self, db: Database, config: MetadataPluginConfig) -> None:
        super().__init__(db, config)
        my_config = ExamplePluginConfig(provider=app_config.provider)
        self.tag = my_config.tag
        self.tag_url = my_config.tag_url

    def extract(
        self, identifier: str, matched_fname: str, current_meta: Metadata
    ) -> Metadata:
        return {"example_tag": {"display_text": self.tag, "url": self.tag_url}}
