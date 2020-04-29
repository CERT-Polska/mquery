import re
import urllib.parse

from typing import Optional

from mwdblib import Malwarecage

from metadata import Metadata, MetadataPlugin


class MalwarecageUploadsMetadata(MetadataPlugin):
    """
    :param mwdb_api_token: API key for 'mquery' user in Malwarecage
    :param mwdb_api_url: API URL accessible from mquery daemon
    :param mwdb_url: Malwarecage URL accessible for mquery users
    """

    __cacheable__ = True

    def __init__(
        self, mwdb_api_token: str, mwdb_api_url: str, mwdb_url: str
    ) -> None:
        super().__init__()
        self.mwdb = Malwarecage(api_url=mwdb_api_url, api_key=mwdb_api_token)
        self.mwdb_url = mwdb_url

    def identify(self, matched_fname: str) -> Optional[str]:
        m = re.search(
            r"/([a-f0-9])/([a-f0-9])/([a-f0-9])/([a-f0-9])/(\1\2\3\4[a-f0-9]+)$",
            matched_fname,
        )
        if not m:
            return None
        return m.group(5)

    def extract(
        self, identifier: str, matched_fname: str, current_meta: Metadata
    ) -> Metadata:
        # '/uploads' Malwarecage directory format
        # /mnt/samples/9/d/c/5/9dc571ae13a62954155999cae9cecc4f0689e2ba9a8940f81d1e564271507a3e
        metadata = {}
        sample = self.mwdb.query(identifier, raise_not_found=False)

        if sample:
            for tag in sample.tags:
                query = urllib.parse.urlencode({"q": f'tag:"{tag}"'})
                # Add queryable metadata for each tag from Malwarecage
                metadata[f"mwdb_tag_{tag}"] = {
                    "display_text": tag,
                    "url": f"{self.mwdb_url}?{query}",
                }

            # Add metadata with link to sample in Malwarecage instance
            metadata[f"mwdb_analysis"] = {
                "display_text": "mwdb",
                "url": f"{self.mwdb_url}sample/{identifier}",
            }

            job_id = current_meta["job"]
            # Add metakey with job identifier
            sample.add_metakey("mquery", job_id)
        return metadata
