import os
import re
from typing import Optional

from ..db import Database
from ..metadata import Metadata, MetadataPlugin, MetadataPluginConfig


class CuckooAnalysisMetadata(MetadataPlugin):
    cacheable = True
    is_extractor = True
    config_fields = {"path": "Root of cuckoo analysis directory."}

    def __init__(self, db: Database, config: MetadataPluginConfig) -> None:
        super().__init__(db, config)
        self.path = config["path"]

    def identify(self, matched_fname: str) -> Optional[str]:
        m = re.search(r"analyses/([0-9]+)/", matched_fname)
        if not m:
            return None
        return m.group(1)

    def extract(
        self, identifier: str, matched_fname: str, current_meta: Metadata
    ) -> Metadata:
        try:
            target = os.readlink(self.path + "{}/binary".format(identifier))
        except OSError:
            return {}

        binary_hash = target.split("/")[-1]

        obj = {
            "cuckoo_hash": {"value": binary_hash},
            "cuckoo_analysis": {
                "display_text": "cuckoo:{}".format(identifier),
                "value": identifier,
            },
        }
        return obj
