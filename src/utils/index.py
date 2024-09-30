import os
import logging
import argparse
import json
from typing import Set, Iterator, Tuple, List, Optional
from pathlib import Path
from lib.ursadb import UrsaDb  # type: ignore
from multiprocessing import Pool


def all_indexed_files(ursa: UrsaDb) -> Set[str]:
    iterator = ursa.query("{}")["iterator"]
    result: Set[str] = set()
    while True:
        pop_result = ursa.pop(iterator, 10000)
        for fpath in pop_result.files:
            result.add(fpath)
        if pop_result.iterator_empty:
            break
    return result


def walk_directory(dir: Path, ignores: List[str]) -> Iterator[Path]:
    """Recursively walks the current directory, while respecting .ursadbignore
    files to selectively ignore some elements.
    """
    if (dir / ".ursadb").exists():
        new_config = (dir / ".ursadb").read_text().strip().split("\n")
        for line in new_config:
            if line.startswith("ignore:"):
                ignores.append(line[len("ignore:") :].strip())
    for elem in dir.iterdir():
        if any(elem.match(ignore) for ignore in ignores):
            continue
        elif elem.is_file():
            yield elem
        elif elem.is_dir():
            for elem in walk_directory(elem, ignores):
                yield elem


def find_new_files(
    existing: Set[str],
    files_root: Path,
    mounted_as: str,
    min_file_size: int,
    max_file_size: int,
) -> Iterator[str]:
    for abspath in walk_directory(files_root.resolve(), [".ursadb"]):
        stat = Path(abspath).stat()
        if stat.st_size > max_file_size:
            continue
        if stat.st_size <= min_file_size:
            continue
        relpath = os.path.relpath(abspath, files_root)
        mounted_path = os.path.join(mounted_as, relpath)
        if mounted_path not in existing:
            yield str(mounted_path)


def index_files(
    proc_params: Tuple[str, List[str], List[str], Path, int]
) -> str:
    ursa_url, types, tags, batch, compact_threshold = proc_params
    ursa = UrsaDb(ursa_url)

    current_datasets = len(
        ursa.execute_command("topology;")["result"]["datasets"]
    )
    if current_datasets > compact_threshold:
        ursa.execute_command("compact smart;")

    type_list = ", ".join(types)
    mounted_names = []
    wipbatch = batch.with_suffix(".wip")
    batch.rename(wipbatch)
    with wipbatch.open() as batchfile:
        for fname in batchfile:
            fname = fname[:-1]  # remove the trailing newline
            fname = fname.replace('"', '\\"')
            mounted_names.append(fname)
    mounted_list = " ".join(f'"{fpath}"' for fpath in mounted_names)
    tag_mod = ""
    if tags:
        tag_list = ",".join(f'"{tag}"' for tag in tags)
        tag_mod = f" with taints [{tag_list}]"
    result = ursa.execute_command(
        f"index {mounted_list} with [{type_list}]{tag_mod} nocheck;"
    )
    if "error" in result:
        wipbatch.rename(batch.with_suffix(".errored"))
        batch.with_suffix(".message").write_text(json.dumps(result, indent=4))
        logging.error(
            "Batch %s errored, see %s for details",
            batch,
            batch.with_suffix(".message"),
        )
    else:
        wipbatch.unlink()
    return str(batch)


def prepare(
    ursadb: str,
    workdir: Path,
    path: Path,
    batch: int,
    min_file_size: int,
    max_file_size: int,
    mounted_as: str,
) -> None:
    if not workdir.exists():
        workdir.mkdir()

    logging.info("Prepare.1: load all indexed files into memory.")
    ursa = UrsaDb(ursadb)
    fileset = all_indexed_files(ursa)

    logging.info("Prepare.2: find all new files.")

    tmpfile = None
    current_batch = 10**20  # As good as infinity.
    new_files = 0
    batch_id = 0
    for f in find_new_files(
        fileset, path, mounted_as, min_file_size, max_file_size
    ):
        if current_batch > batch:
            if tmpfile is not None:
                tmpfile.close()
            current_batch = 0
            tmppath = workdir / f"batch_{batch_id:010}.txt"
            tmpfile = tmppath.open(mode="w")
            batch_id += 1

        assert tmpfile is not None  # Let mypy know the obvious.
        tmpfile.write(f"{f}\n")
        current_batch += 1
        new_files += 1

    if tmpfile is not None:
        tmpfile.close()

    logging.info(
        "Prepare.3: Got %s files in %s batches to index.", new_files, batch_id
    )


def index(
    ursadb: str,
    workdir: Path,
    types: List[str],
    tags: List[str],
    workers: int,
    working_datasets: Optional[int],
) -> None:
    logging.info("Index.1: Determine compacting threshold.")
    if working_datasets is None:
        working_datasets = workers * 20 + 40

    ursa = UrsaDb(ursadb)
    current_datasets = len(
        ursa.execute_command("topology;")["result"]["datasets"]
    )
    compact_threshold = current_datasets + working_datasets

    logging.info("Index.1: Compact threshold = %s.", compact_threshold)

    logging.info("Index.2: Find prepared batches.")
    indexing_jobs = []
    for batch in workdir.glob("*.txt"):
        indexing_jobs.append((ursadb, types, tags, batch, compact_threshold))

    logging.info("Index.2: Got %s batches to run.", len(indexing_jobs))

    logging.info("Index.3: Run index commands with %s workers.", workers)
    pool = Pool(processes=workers)
    done = 0
    total = len(indexing_jobs)
    for batchid in pool.imap_unordered(
        index_files, indexing_jobs, chunksize=1
    ):
        done += 1
        logging.info("Index.4: Batch %s done [%s/%s].", batchid, done, total)

    if list(workdir.iterdir()):
        logging.info("Index.5: Workdir not removed, because it's not empty.")
    else:
        logging.info("Index.5: Unlinking the workdir.")
        workdir.rmdir()


def main() -> None:
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Reindex local files.")
    parser.add_argument(
        "--mode",
        help="Mode of operation. Only prepare batches, index them, or both.",
        default="prepare-and-index",
        choices=["prepare", "index", "prepare-and-index"],
    )
    # switches relevant for both "prepare" and "index" modes
    parser.add_argument(
        "--ursadb",
        help="URL of the ursadb instance.",
        default="tcp://localhost:9281",
    )
    parser.add_argument(
        "--workdir", help="Path to a working directory.", default=None
    )
    # switches relevant only for "prepare" mode
    parser.add_argument(
        "--batch", help="Size of indexing batch.", type=int, default=1000
    )
    parser.add_argument(
        "--path", help="Path of samples to be indexed.", default=None
    )
    parser.add_argument(
        "--path-mount",
        help="Path to the samples to be indexed, as seen by ursadb (if different).",
        default=None,
    )
    parser.add_argument(
        "--min-file-size-mb",
        type=int,
        help="Minimum file size, in MB, to index. 0 By default.",
        default=0,
    )
    parser.add_argument(
        "--max-file-size-mb",
        type=int,
        help="Maximum file size, in MB, to index. 128 By default.",
        default=128,
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
        "--workers",
        help="Number of parallel indexing jobs.",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--working-datasets",
        help="Numer of working datasets (uses sane value by default).",
        type=int,
        default=None,
    )

    args = parser.parse_args()
    types = list(set(args.types))

    if args.workdir is None:
        logging.error("--workdir is a required parameter")
        return

    try:
        ursa = UrsaDb(args.ursadb)
        ursa.status()
    except Exception:
        logging.error("Can't connect to ursadb instance at %s", args.ursadb)

    if args.mode == "prepare" or args.mode == "prepare-and-index":
        # Path must exist
        if args.path is None:
            logging.error("Path (--path) is a required parameter.")
            return

        if args.path_mount is not None:
            path_mount = args.path_mount
        else:
            path_mount = args.path

        path = Path(args.path)
        if not path.exists:
            logging.error("Path (--path) %s does not exist.", args.path)
            return

        # We're starting a new indexing operation. Workdir must not exist.
        workdir = Path(args.workdir)
        if workdir.exists() and list(workdir.iterdir()):
            logging.error(
                "Workdir %s already exists and is not empty. Remove it or choose another one.",
                args.workdir,
            )
            return

        max_file_size = args.max_file_size_mb * 1024 * 1024
        min_file_size = args.min_file_size_mb * 1024 * 1024
        assert min_file_size < max_file_size
        prepare(
            args.ursadb,
            workdir,
            path,
            args.batch,
            min_file_size,
            max_file_size,
            path_mount,
        )

    if args.mode == "index" or args.mode == "prepare-and-index":
        # By default use only all index types.
        if not args.types:
            types = ["gram3", "text4", "wide8", "hash4"]

        # We're continuing an existing operation. Workdir must exist.
        workdir = Path(args.workdir)
        if not workdir.exists():
            logging.error(
                "Running with mode=index, but workdir %s doesn't exist",
                args.workdir,
            )
            return

        index(
            args.ursadb,
            workdir,
            types,
            args.tags,
            args.workers,
            args.working_datasets,
        )

        logging.info("Indexing finished. Consider compacting the database now")


if __name__ == "__main__":
    main()
