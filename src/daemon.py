#!/usr/bin/env python
import argparse
from multiprocessing import Process
import logging
from redis import Redis
from rq import Connection, Worker  # type: ignore

from .util import setup_logging
from . import tasks
from .config import app_config


def start_worker(group_id: str, process_index: int) -> None:
    setup_logging()
    logging.info(
        "Agent [%s] running (process %s)...", group_id, process_index
    )

    with Connection(Redis(app_config.redis.host, app_config.redis.port)):
        w = Worker([group_id])
        w.work()


def main() -> None:
    """Spawns a new agent process. Use argv if you want to use a different
    group_id (it's `default` by default).
    """

    parser = argparse.ArgumentParser(description="Start mquery daemon.")
    parser.add_argument(
        "group_id",
        help="Name of the agent group to join to",
        nargs="?",
        default="default",
    )
    parser.add_argument(
        "-s",
        "--scale",
        type=int,
        help="Specifies the number of worker processes to start.",
        default=1,
    )
    parser.add_argument(
        "-i",
        "--with-indexer",
        action="store_true",
        help="Also start the index worker. Must run in the same filesystem as ursadb.",
    )

    args = parser.parse_args()

    # Initial registration of the worker group.
    # The goal is to make the web UI aware of this worker and its configuration.
    tasks.make_agent(args.group_id).register()

    children = [
        Process(target=start_worker, args=(args.group_id, i))
        for i in range(args.scale)
    ]
    if args.with_indexer:
        indexer_name = args.group_id + ":indexer"
        children.append(Process(target=start_worker, args=(indexer_name, 0)))
    for child in children:
        child.start()
    for child in children:
        child.join()


if __name__ == "__main__":
    main()
