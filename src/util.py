import logging
import hashlib
from typing import Dict, Any


LOG_FORMAT = "[%(asctime)s][%(levelname)s] %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level=logging.INFO) -> None:
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt=LOG_DATEFMT)


def mquery_version() -> str:
    return "1.6.0"


def make_sha256_tag(filename: str) -> Dict[str, Any]:
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return {"display_text": sha256_hash.hexdigest(), "hidden": True}
