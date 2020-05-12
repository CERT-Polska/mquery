import re
from db import Database
from metadata import MetadataPlugin, MetadataPluginConfig
from typing import Optional


class RegexBlacklistPlugin(MetadataPlugin):
    is_filter = True
    config_fields = {
        "blacklist_pattern": "Regular expression for files that should be ignored",
    }

    def __init__(self, db: Database, config: MetadataPluginConfig) -> None:
        super().__init__(db, config)
        self.blacklist_pattern = config["blacklist_pattern"]

    def filter(self, orig_name: str, file_path: str) -> Optional[str]:
        if re.search(self.blacklist_pattern, orig_name):
            return None
        return file_path
