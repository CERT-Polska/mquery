import os
import re

from typing import Optional

from metadata import Metadata, MetadataPlugin


class CuckooAnalysisMetadata(MetadataPlugin):
    def __init__(self, path):
        super().__init__()
        self.path = path

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
