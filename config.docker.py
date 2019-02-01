import os

from metadata.cuckoo_analysis import CuckooAnalysisMetadata

BACKEND = 'tcp://ursadb:9281'
REDIS_HOST = 'redis'
REDIS_PORT = 6379
SECRET_KEY = os.environ['SECRET_KEY']
METADATA_EXTRACTORS = [
    CuckooAnalysisMetadata("/mnt/samples/analyses/")
]
