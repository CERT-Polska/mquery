import os

from metadata.cuckoo_analysis import CuckooAnalysisMetadata

BACKEND = 'tcp://ursadb:9281'
REDIS_HOST = 'redis'
REDIS_PORT = 6379
SECRET_KEY = os.environ['SECRET_KEY']
INDEXABLE_PATHS = [p for p in os.environ.get('INDEXABLE_PATHS', '').split(';') if p.strip()]
INDEX_TYPE = ['gram3', 'hash4', 'text4', 'wide8']
METADATA_EXTRACTORS = [
    CuckooAnalysisMetadata("/mnt/samples/analyses/")
]
