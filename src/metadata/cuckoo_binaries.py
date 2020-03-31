import re
from metadata import Metadata
from typing import List, Any


class CuckooBinariesMetadata(Metadata):
    __depends_on__: List[Any] = []

    def __init__(self):
        super().__init__()

    def extract(self, matched_fname, current_meta):
        m = re.search(r"/binaries/([a-f0-9]+)$", matched_fname)
        if not m:
            return {}
        binary_hash = m.group(1)
        return {"cuckoo_hash": {"value": binary_hash}}
