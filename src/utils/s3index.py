import os
import logging
import argparse
import shutil
from typing import Set, List
from pathlib import Path
from lib.ursadb import UrsaDb
from minio import Minio  # type: ignore


def all_indexed_names(ursa: UrsaDb) -> Set[str]:
    """Gets all unique filenames of indexed files."""
    iterator = ursa.query("{}")["iterator"]
    result: Set[str] = set()
    while True:
        pop_result = ursa.pop(iterator, 10000)
        if pop_result.iterator_empty:
            break
        for fpath in pop_result.files:
            result.add(os.path.basename(fpath))
    return result


def process_and_delete_batch(
    ursa: UrsaDb,
    batch: List[str],
    compact_threshold: int,
    types: List[str],
    tags: List[str],
) -> None:
    """Index a list of file paths with specified parameters."""
    logging.info("Processing batch of %s files", len(batch))
    current_datasets = len(
        ursa.execute_command("topology;")["result"]["datasets"]
    )
    if current_datasets > compact_threshold:
        ursa.execute_command("compact smart;")

    type_list = ", ".join(types)
    batch_list = " ".join(f'"{bfile}"' for bfile in batch)
    tag_mod = ""
    if tags:
        tag_list = ",".join(f'"{tag}"' for tag in tags)
        tag_mod = f" with taints [{tag_list}]"
    result = ursa.execute_command(
        f"index {batch_list} with [{type_list}]{tag_mod} nocheck;"
    )
    if "error" in result:
        logging.error("Batch %s errored: %s", result["error"])
    for bfile in batch:
        os.unlink(bfile)


def main() -> None:
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Index files from s3.")
    parser.add_argument(
        "--ursadb",
        help="URL of the ursadb instance.",
        default="tcp://localhost:9281",
    )
    parser.add_argument("--s3-url", help="S3 server url.", required=True)
    parser.add_argument("--s3-secret-key", help="Secret key.", required=True)
    parser.add_argument("--s3-access-key", help="Access key.", required=True)
    parser.add_argument("--s3-bucket", help="Bucket name.", required=True)
    parser.add_argument(
        "--s3-secure", help="Use https (1 or 0)?.", type=int, default=True
    )
    parser.add_argument(
        "--workdir", help="Path to a working directory.", default=None
    )
    parser.add_argument(
        "--batch", help="Size of indexing batch.", type=int, default=1000
    )
    # switches relevant only for "index" mode
    parser.add_argument(
        "--type",
        dest="types",
        help="Index types. By default [gram3, text4, wide8, hash4]",
        action="append",
        default=[],
        choices=["gram3", "text4", "hash4", "wide8"],
    )
    parser.add_argument(
        "--tag",
        dest="tags",
        help="Additional tags for indexed datasets.",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--working-datasets",
        help="Numer of working datasets (uses sane value by default).",
        type=int,
        default=40,
    )

    args = parser.parse_args()
    types = list(set(args.types))
    
    if not args.types:
        types = ["gram3", "text4", "wide8", "hash4"]
        
    if args.workdir is None:
        logging.error("--workdir is a required parameter")
        return

    ursa = UrsaDb(args.ursadb)
    fileset = all_indexed_names(ursa)

    current_datasets = len(
        ursa.execute_command("topology;")["result"]["datasets"]
    )
    compact_threshold = current_datasets + args.working_datasets

    client = Minio(
        args.s3_url,
        args.s3_access_key,
        args.s3_secret_key,
        secure=int(args.s3_secure),
    )

    workdir = Path(args.workdir)
    if workdir.exists() and list(workdir.iterdir()):
        logging.error(
            "Workdir %s already exists and is not empty. Remove it or choose another one.",
            args.workdir,
        )
        return
    if not workdir.exists():
        workdir.mkdir()

    batch = []
    for s3_obj in client.list_objects(args.s3_bucket):
        if s3_obj.object_name in fileset:
            continue

        f_in = client.get_object(args.s3_bucket, s3_obj.object_name)
        try:
            next_path = workdir / s3_obj.object_name
            with open(next_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            batch.append(str(next_path))
        finally:
            f_in.close()
            f_in.release_conn()

        if len(batch) == args.batch:
            process_and_delete_batch(
                ursa, batch, compact_threshold, types, args.tags
            )
            batch = []

    if len(batch):
        process_and_delete_batch(
            ursa, batch, compact_threshold, types, args.tags
        )

    if list(workdir.iterdir()):
        logging.info("Workdir not removed, because it's not empty.")
    else:
        logging.info("Unlinking the workdir.")
        workdir.rmdir()


if __name__ == "__main__":
    main()
