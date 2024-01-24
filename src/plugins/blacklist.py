import re
from typing import Optional

from ..metadata import MetadataPlugin, MetadataPluginConfig
from ..db import Database


class RegexBlacklistPlugin(MetadataPlugin):
    """Can be used to ignore files with filenames matching a certain
    pattern. For example, to ignore all pcap files, set blacklist_pattern
    to "[.]pcap$".
    """

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
