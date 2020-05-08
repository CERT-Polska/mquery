import logging


LOG_FORMAT = "[%(asctime)s][%(levelname)s] %(message)s"
LOG_DATEFMT = "%d/%m/%Y %H:%M:%S"


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO, format=LOG_FORMAT, datefmt=LOG_DATEFMT
    )


def mquery_version():
    return "1.1.0"
