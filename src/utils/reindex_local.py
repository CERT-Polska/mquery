import os
import logging
import argparse
from typing import Set, Iterator, Tuple, List
from pathlib import Path
from lib.ursadb import UrsaDb
from multiprocessing import Pool
from tempfile import NamedTemporaryFile


def all_indexed_files(ursa: UrsaDb) -> Set[str]:
    iterator = ursa.query("{}")["iterator"]
    result: Set[str] = set()
    while True:
        pop_result = ursa.pop(iterator, 5000)
        if pop_result.iterator_empty:
            break
        for fpath in pop_result.files:
            result.add(fpath)
    return result


def walk_directory(dir: Path, ignores: List[str]) -> Iterator[Path]:
    """Recursively walks the current directory, while respecting .ursadbignore
    files to selectively ignore some elements """
    if (dir / ".ursaignore").exists():
        new_ignores = (dir / ".ursaignore").read_text().strip().split("\n")
        ignores = ignores + new_ignores
    for elem in dir.iterdir():
        if any(elem.match(ignore) for ignore in ignores):
            continue
        elif elem.is_file():
            yield elem
        elif elem.is_dir():
            for elem in walk_directory(elem, ignores):
                yield elem


def find_new_files(
    existing: Set[str], files_root: str, mounted_as: str
) -> Iterator[str]:
    files_root = os.path.abspath(files_root)
    mounted_as = os.path.abspath(mounted_as)
    for abspath in walk_directory(Path(files_root), [".ursaignore"]):
        relpath = os.path.relpath(str(abspath), files_root)
        fpath = os.path.join(mounted_as, relpath)
        if fpath not in existing:
            yield fpath


def index_files(proc_params: Tuple[str, List[str], str, int]) -> None:
    ursa_url, types, mounted_name, ndx = proc_params
    ursa = UrsaDb(ursa_url)
    with_ = ", ".join(types)
    ursa.execute_command(
        f'index from list "{mounted_name}" with [{with_}] nocheck;'
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Reindex local files.")
    parser.add_argument("path", help="Path of samples to be indexed.")
    parser.add_argument(
        "--path-mount",
        help="Path to the samples to be indexed, as seen by ursadb (if different).",
        default=None,
    )
    parser.add_argument(
        "--ursadb",
        help="URL of the ursadb instance.",
        default="tcp://localhost:9281",
    )
    parser.add_argument(
        "--tmpdir", help="Path to used tmpdir.", default="/tmp"
    )
    parser.add_argument(
        "--tmpdir-mount",
        help="Path to used tmpdir, as seen by ursadb (if different)",
        default=None,
    )
    parser.add_argument(
        "--batch", help="Size of indexing batch.", type=int, default=1000
    )
    parser.add_argument(
        "--type",
        dest="types",
        help="Additional index types.",
        action="append",
        default=["gram3"],
        choices=["gram3", "text4", "hash4", "wide8"],
    )
    parser.add_argument(
        "--workers",
        help="Number of parallel indexing jobs.",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--dry-run",
        help="Don't index, only print filenames.",
        action="store_true",
    )

    args = parser.parse_args()

    tmpdir_mount = args.tmpdir_mount or args.tmpdir
    path_mount = args.path_mount or args.path

    logging.info("Stage 1: load all indexed files into memory.")
    ursa = UrsaDb(args.ursadb)
    fileset = all_indexed_files(ursa)

    logging.info("Stage 2: find all new files.")

    tmpfile = None
    tmpfiles = []
    current_batch = 10 ** 20  # As good as infinity.
    new_files = 0
    for f in find_new_files(fileset, args.path, path_mount):
        if args.dry_run:
            print(f)
            continue
        if current_batch > args.batch:
            current_batch = 0
            if tmpfile:
                tmpfile.close()
            tmpfile = NamedTemporaryFile(
                mode="w", dir=args.tmpdir, delete=False
            )
            tmpfiles.append(tmpfile.name)

        assert tmpfile is not None  # Let mypy know the obvious.
        tmpfile.write(f"{f}\n")
        current_batch += 1
        new_files += 1

    logging.info(
        "Got %s files in %s batches to index.", new_files, len(tmpfiles)
    )
    if args.dry_run:
        return
    del fileset

    indexing_jobs = []
    for ndx, tmppath in enumerate(tmpfiles):
        mounted_name = os.path.join(
            tmpdir_mount, os.path.relpath(tmppath, args.tmpdir)
        )
        indexing_jobs.append((args.ursadb, args.types, mounted_name, ndx))
        logging.info(f"Batch %s: %s", ndx, mounted_name)

    logging.info("Stage 3: Run index command in parallel.")
    pool = Pool(processes=args.workers)
    done = 0
    total = len(indexing_jobs)
    for batchid in pool.imap_unordered(
        index_files, indexing_jobs, chunksize=1
    ):
        done += 1
        logging.info(f"Batch %s done [%s/%s].", batchid, done, total)

    logging.info("Stage 4: Cleanup.")
    for f in tmpfiles:
        os.unlink(f)


if __name__ == "__main__":
    main()
