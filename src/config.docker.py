import os

from metadata.cuckoo_analysis import CuckooAnalysisMetadata

SKIP_YARA = bool(os.environ.get("SKIP_YARA", False))
BACKEND = os.environ.get("MQUERY_BACKEND", "tcp://ursadb:9281")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
METADATA_EXTRACTORS = [CuckooAnalysisMetadata("/mnt/samples/analyses/")]
