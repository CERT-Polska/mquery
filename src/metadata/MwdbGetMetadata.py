import logging

import requests
import urllib
from metadata import Metadata


class MWDBGetMetadata(Metadata):
    __depends_on__ = ["CuckooBinariesMetadata"]

    def __init__(self, mwdb_api_token: str) -> None:
        super().__init__()
        self.token = mwdb_api_token

    def extract(self, matched_fname, dependent_meta):
        if not dependent_meta.get("cuckoo_hash"):
            return {}

        hash = dependent_meta.get("cuckoo_hash")["value"]

        cached = self.cache_fetch(hash)

        if cached:
            return cached

        if not self.token:
            logging.error(
                "MWDB metadata not fetched, MWDB_API_TOKEN variable was not set"
            )

        mwdb_url = "https://mwdb.cert.pl/api/file/{}"
        obj = {}

        try:
            headers = {"Authorization": "Bearer {}".format(self.token)}
            res = requests.get(
                mwdb_url.format(hash), headers=headers, verify=False
            )
            res.raise_for_status()
        except requests.HTTPError:
            logging.exception("Failed to download MWDB metadata")
            return {}

        for tag in res.json().get("tags"):
            obj["mwdb_tag_{}".format(tag["tag"])] = {
                "display_text": tag["tag"],
                "url": "https://mwdb.cert.pl/search?"
                + urllib.parse.urlencode({"q": 'tag:"' + tag["tag"] + '"'}),
            }

        obj["mwdb_analysis"] = {
            "display_text": "mwdb",
            "url": "https://mwdb.cert.pl/sample/{}".format(
                dependent_meta.get("cuckoo_hash")["value"]
            ),
        }

        self.cache_store(hash, obj)
        return obj
