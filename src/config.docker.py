import os
from typing import List
from metadata import Metadata
from metadata.cuckoo_analysis import CuckooAnalysisMetadata
from metadata.mwdb import MWDBAnalysisMetadata
from metadata.cuckoo_binaries import CuckooBinariesMetadata


SKIP_YARA = bool(os.environ.get("SKIP_YARA", False))
BACKEND = os.environ.get("MQUERY_BACKEND", "tcp://ursadb:9281")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
JOB_EXPIRATION_MINUTES = int(
    os.environ.get("JOB_EXPIRATION_MINUTES", 3600)
)  # 60 hours

METADATA_EXTRACTORS: List[Metadata] = []

if bool(os.environ.get("ENABLE_PLUGINS", False)):
    if "CUCKOO_ROOT" in os.environ:
        METADATA_EXTRACTORS.append(
            CuckooAnalysisMetadata(os.environ["CUCKOO_ROOT"])
        )

    METADATA_EXTRACTORS.append(CuckooBinariesMetadata())

    if "MWDB_API_KEY" in os.environ:
        METADATA_EXTRACTORS.append(
            MWDBAnalysisMetadata(os.environ["MWDB_API_KEY"]),
        )
