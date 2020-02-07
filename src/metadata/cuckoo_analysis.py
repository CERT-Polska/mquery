import os
import re

from metadata import Metadata


class CuckooAnalysisMetadata(Metadata):
    __depends_on__ = []

    def __init__(self, path):
        super().__init__()
        self.path = path

    def extract(self, matched_fname, current_meta):
        m = re.search(r"analyses/([0-9]+)/", matched_fname)

        if not m:
            return {}

        analysis_id = int(m.group(1))

        cached = self.cache_fetch(analysis_id)

        if cached:
            return cached

        try:
            target = os.readlink(self.path + "{}/binary".format(analysis_id))
        except OSError:
            return {}

        binary_hash = target.split('/')[-1]

        obj = {
            "cuckoo_hash": {"value": binary_hash},
            "cuckoo_analysis": {"display_text": "cuckoo:{}".format(analysis_id), "value": analysis_id}
        }

        self.cache_store(analysis_id, obj)

        return obj
