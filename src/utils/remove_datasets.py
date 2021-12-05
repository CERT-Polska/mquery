"""
"Cleans" unneccesary dataset files in the index directory.
It doing that by checking the IDs of all files in the directory,
and validating if they exist in "db.ursa" file.

Just update the "index_basepath" variable, and run the script without arguments.
"""
import json
import os
import re
import logging
from typing import List

index_basepath = "/mnt/index/"

get_id_from_set_fmt = r"set.([0-9a-zA-Z]*).db.ursa"
get_id_from_files_fmt = r"files.set.([0-9a-zA-Z]*).db.ursa"
get_id_from_iterator_fmt = r"iterator.([0-9a-zA-Z]*).db.ursa"
get_id_from_itermeta_fmt = r"itermeta.([0-9a-zA-Z]*).db.ursa"
get_id_from_namecache_fmt = r"namecache.files.set.([0-9a-zA-Z]*).db.ursa"
get_id_from_gram3_fmr = r"gram3.set.([0-9a-zA-Z]*).db.ursa"
get_id_from_hash4_fmt = r"hash4.set.([0-9a-zA-Z]*).db.ursa"
get_id_from_text4_fmt = r"text4.set.([0-9a-zA-Z]*).db.ursa"
get_id_from_wide8_fmt = r"wide8.set.([0-9a-zA-Z]*).db.ursa"

all_fmts = [
    get_id_from_set_fmt,
    get_id_from_files_fmt,
    get_id_from_iterator_fmt,
    get_id_from_itermeta_fmt,
    get_id_from_namecache_fmt,
    get_id_from_gram3_fmr,
    get_id_from_hash4_fmt,
    get_id_from_text4_fmt,
    get_id_from_wide8_fmt,
]


def get_datasets() -> List[str]:
    with open(os.path.join(index_basepath, "db.ursa"), "r") as f:
        db = json.load(f)
    datasets = db["datasets"]
    return list(
        map(lambda x: re.search(get_id_from_set_fmt, x).group(1), datasets)
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    datasets = get_datasets()

    for fname in os.listdir(index_basepath):
        if fname == "db.ursa":
            continue
        fpath = os.path.join(index_basepath, fname)

        try:
            id = next(
                filter(None, [re.search(fmt, fname) for fmt in all_fmts])
            ).group(1)
        except:
            # Should happen if non-ursadb files exists in index directory.
            continue

        if id in datasets:
            # Legit dataset file.
            continue

        logging.info(f"Removing {fname}")
        os.remove(fpath)


if __name__ == "__main__":
    main()
