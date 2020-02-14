import logging

from itsdangerous import JSONWebSignatureSerializer
from redis import StrictRedis

import config #  type: ignore


LOG_FORMAT = "[%(asctime)s][%(levelname)s] %(message)s"
LOG_DATEFMT = "%d/%m/%Y %H:%M:%S"


def setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt=LOG_DATEFMT)


def make_redis() -> StrictRedis:
    return StrictRedis(host=config.REDIS_HOST, port=config.REDIS_PORT, decode_responses=True)

