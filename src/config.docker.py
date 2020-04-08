import os
from typing import List
from metadata import Metadata


SKIP_YARA = bool(os.environ.get("SKIP_YARA", False))
BACKEND = os.environ.get("MQUERY_BACKEND", "tcp://ursadb:9281")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
JOB_EXPIRATION_MINUTES = int(
    os.environ.get("JOB_EXPIRATION_MINUTES", 3600)
)  # 60 hours

METADATA_EXTRACTORS: List[Metadata] = []
