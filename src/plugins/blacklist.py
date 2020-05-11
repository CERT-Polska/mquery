import re
from db import Database
from metadata import MetadataPlugin, MetadataPluginConfig


class RegexBlacklistPlugin(MetadataPlugin):
    is_filter = True
    config_fields = {
        "blacklist_pattern": "Regular expression for files that should be ignored",
    }

    def __init__(self, db: Database, config: MetadataPluginConfig) -> None:
        super().__init__(db, config)
        self.blacklist_pattern = config["blacklist_pattern"]

    def filter(self, matched_fname: str) -> bool:
        if re.search(self.blacklist_pattern, matched_fname,) is not None:
            return False
        return True
