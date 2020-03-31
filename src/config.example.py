from typing import List
from metadata import Metadata

SKIP_YARA = False
BACKEND = "tcp://127.0.0.1:9281"
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
METADATA_EXTRACTORS: List[Metadata] = []
JOB_EXPIRATION_MINUTES = 3600  # 60 hours
