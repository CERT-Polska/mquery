import logging
from lib.ursadb import UrsaDb
import time
import argparse


def main() -> None:
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Keep the database lean.")
    parser.add_argument(
        "--ursadb",
        help="URL of the ursadb instance.",
        default="tcp://localhost:9281",
    )

    args = parser.parse_args()
    ursa = UrsaDb(args.ursadb)
    stage = 0
    last_datasets = None
    while True:
        datasets = set(
            ursa.execute_command("topology;")["result"]["datasets"].keys()
        )
        if last_datasets:
            removed = list(last_datasets - datasets)
            created = list(datasets - last_datasets)
            logging.info("%s => %s", removed, created)
        logging.info("Stage %s: %s datasets left.", stage, len(datasets))
        if last_datasets and datasets == last_datasets:
            logging.info("Finally, a fixed point! Returning...")
            return

        start = time.time()
        ursa.execute_command("compact all;")
        end = time.time()
        logging.info("Compacting took %s seconds...", (end - start))
        stage += 1
        last_datasets = datasets


if __name__ == "__main__":
    main()
