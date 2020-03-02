from metadata.cuckoo_analysis import CuckooAnalysisMetadata

SKIP_YARA = False
BACKEND = "tcp://127.0.0.1:9281"
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
METADATA_EXTRACTORS = [CuckooAnalysisMetadata("/opt/mw/samples/analyses/")]
