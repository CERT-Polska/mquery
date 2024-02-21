from ..db import Database
from ..metadata import Metadata, MetadataPlugin, MetadataPluginConfig


class ExampleTagPlugin(MetadataPlugin):
    """This plugin is a minimal (almost) example of extractor plugin.
    It will tag every processed file with configured tag and URL.
    """

    cacheable = True
    is_extractor = True
    config_fields = {
        "tag": "Everything will be tagged using that tag",
        "tag_url": "Tag URL e.g. http://google.com?q={tag}",
    }

    def __init__(self, db: Database, config: MetadataPluginConfig) -> None:
        super().__init__(db, config)
        self.tag = config["tag"]
        self.tag_url = config["tag_url"]

    def extract(
        self, identifier: str, matched_fname: str, current_meta: Metadata
    ) -> Metadata:
        return {"example_tag": {"display_text": self.tag, "url": self.tag_url}}
