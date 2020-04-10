import re

from ..metadata import MetadataPlugin


class CuckooBinariesMetadata(MetadataPlugin):
    __cacheable__ = False

    def identify(self, matched_fname):
        m = re.search(r"/binaries/([a-f0-9]+)$", matched_fname)
        if not m:
            return None
        return m.group(1)

    def extract(self, identifier, matched_fname, current_meta):
        return {"cuckoo_hash": {"value": identifier}}
