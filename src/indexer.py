#!/usr/bin/env python
import argparse
import logging
from multiprocessing import Pool
from time import sleep
from zmq.error import Again  # type: ignore
from os import getpid

from .db import Database
from .plugins import PluginManager
from .util import setup_logging
from .models.queuedfile import QueuedFile
from .lib.ursadb import UrsaDb
from .config import app_config


COMPACT_THRESHOLD = 0
"""Global variable dependeng on number of workers"""


def index_batch(
    job: tuple[list[QueuedFile], list[str], list[str]],
) -> list[QueuedFile]:
    batch, index_types, tags = job
    pid = getpid()
    assert (
        batch
    ), "This function shouldn't be called without files, likely a bug."

    paths = [f.path for f in batch]

    db = Database(app_config.redis.host, app_config.redis.port)
    ursa = UrsaDb(app_config.mquery.backend)
    plugins = PluginManager(app_config.mquery.plugins, db)
    db.engine.dispose()

    while True:
        try:
            while True:
                current_datasets = len(ursa.datasets())
                if current_datasets <= COMPACT_THRESHOLD:
                    break
                ursa.execute_command("compact smart;")
            break
        except Again:
            logging.info("%s: (worker temporarily blocked)", pid)
            sleep(15)

    ursadb_batch = []
    for file_path in paths:
        final_path = plugins.filter(file_path)
        if final_path is None:
            logging.debug("%s: Filtering out file %s", pid, file_path)
            continue
        ursadb_batch.append(final_path)

    logging.debug("%s: Batch preprocessed, asking ursadb to index it.", pid)

    while True:
        try:
            ursa.index(
                ursadb_batch,
                index_types=index_types,
                tags=tags,
                verify_duplicates=False,
            )
            logging.debug("%s: Ursadb indexing completed", pid)
            break
        except Again:
            logging.info("%s: (worker temporarily blocked)", pid)
            sleep(15)

    plugins.cleanup()
    logging.debug("%s Cleanup completed", pid)

    return batch


def indexer_main(group_id: str, scale: int) -> None:
    """Do the indexing in an infinite loop."""
    logging.info("Starting indexer for group %s", group_id)
    logging.info("Workers: %s", scale)

    global COMPACT_THRESHOLD
    COMPACT_THRESHOLD = scale * 20 + 40
    logging.info("Compact threshold: %s", COMPACT_THRESHOLD)

    db = Database(app_config.redis.host, app_config.redis.port)

    # How many files should one worker index at once
    BATCH_SIZE = 1000

    # Don't get all the files from the database at once, to avoid huge queries
    LIMIT = scale * 100 * BATCH_SIZE

    while True:
        pending = db.get_pending_files(group_id, LIMIT)
        if not pending:
            logging.debug("No pending files left.")
            sleep(15)  # Wait a bit to collect some files.
            continue

        index_types, tags = pending[0].index_types, pending[0].tags
        logging.debug("We are indexing type=%s, tags=%s", index_types, tags)

        batches = []
        next_batch = []
        for f in pending:
            next_batch.append(f)
            if len(next_batch) >= BATCH_SIZE:
                batches.append(next_batch)
                next_batch = []

        if next_batch:
            batches.append(next_batch)

        types_str = ",".join(type for type in index_types)
        tags_str = ",".join(tag for tag in tags)
        logging.info(
            "[0/%s] Collected batches (%s files), with [%s], with tags [%s]",
            len(batches),
            len(pending),
            types_str,
            tags_str,
        )

        jobs = [(batch, index_types, tags) for batch in batches]

        done = 0
        pool = Pool(processes=scale)
        for completed_batch in pool.imap_unordered(
            index_batch, jobs, chunksize=1
        ):
            done += 1
            db.remove_from_pending(completed_batch)
            logging.info("[%s/%s] Batch completed.", done, len(batches))

        logging.info("[%s/%s] Indexing completed", done, len(batches))


def main() -> None:
    """Spawns a new indexer process. Indexer will work in the background all the time."""

    parser = argparse.ArgumentParser(
        description="Start mquery indexer worker."
    )
    parser.add_argument(
        "group_id",
        help="Name of the agent group to join to",
        nargs="?",
        default="default",
    )
    parser.add_argument(
        "--scale",
        type=int,
        help="Specifies the number of concurrent workers to use for yara matching.",
        default=1,
    )
    args = parser.parse_args()

    setup_logging(logging.INFO)
    indexer_main(args.group_id, args.scale)


if __name__ == "__main__":
    main()
