import logging

import requests
import urllib
import mwdblib
from mwdblib import Malwarecage
from metadata import Metadata


class MWDBIntegrateMetadata(Metadata):
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
            return {}

        try:
            api = mwdblib.MalwarecageAPI(
                api_url="https://mwdb.cert.pl/api/", api_key=self.token
            )
            mwdb = Malwarecage(api=api)
            file = mwdb.query_file(hash)

            job_id = dependent_meta["job"]
            file.add_metakey("mquery", job_id)

        except:
            logging.exception("Failed to post mquery metadata")
            return {}

        obj = {}

        obj["mwdb_sample"] = {
            "display_text": "mwdb",
            "url": "http://mwdb.cert.pl/sample/{}".format(job_id),
        }
        self.cache_store(hash, obj)
        return obj
