#!/usr/bin/python3

import argparse
import time
import requests
import os


class OutputSettings:
    def __init__(self):
        self.print_hash = True
        self.print_matches = False
        self.print_filenames = False
        self.save_to_directory = None


def query(mquery_server: str, yara_rule: str) -> str:
    """ Queries mquery server and returns a new job ID """
    res = requests.post(
        f"{mquery_server}/api/query",
        json={
            "method": "query",
            "raw_yara": yara_rule,
            "taint": None,
            "priority": "normal",
            "method": "query",
        },
    ).json()
    if "error" in res:
        raise RuntimeError("Query error: " + res["error"])

    return res["query_hash"]


def process_job(
    mquery_server: str, job_id: str, output: OutputSettings
) -> None:
    offset = 0

    while True:
        MAX_SAMPLES = 50
        out = requests.get(
            f"{mquery_server}/api/matches/{job_id}",
            {"offset": offset, "limit": MAX_SAMPLES},
        ).json()

        if "error" in out:
            raise RuntimeError(out["error"])

        matches = out["matches"]
        for match in matches:
            sha256 = match["meta"]["sha256"]["display_text"]
            line = sha256

            file_path = match["file"]
            if output.print_filenames:
                line += f" {file_path}"

            if output.print_matches:
                for matched_rule in match["matches"]:
                    line += f" {matched_rule}"

            print(line)

            if output.save_to_directory is not None:
                with open(
                    f"{output.save_to_directory}/{sha256}", "wb"
                ) as outf:
                    r = requests.get(
                        f"{mquery_server}/api/download",
                        {
                            "job_id": job_id,
                            "ordinal": offset,
                            "file_path": file_path,
                        },
                    )
                    outf.write(r.content)

            offset += 1

        FINISHED_STATES = ["cancelled", "failed", "done", "removed"]
        if not matches:
            if out["job"]["status"] in FINISHED_STATES:
                break

            time.sleep(1.0)


def main():
    parser = argparse.ArgumentParser(description="")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--yara", help="Yara rule to use for query")
    group.add_argument("--job", help="Job ID to print or download")

    parser.add_argument(
        "--mquery",
        default="http://localhost",
        help="Change mquery server address",
    )
    parser.add_argument(
        "--print-filenames",
        default=False,
        action="store_true",
        help="Also print filenames",
    )
    parser.add_argument(
        "--print-matches",
        default=False,
        action="store_true",
        help="Also print matched rules",
    )
    parser.add_argument(
        "--save",
        default=None,
        help="Download samples and save to the provided directory",
    )

    args = parser.parse_args()
    output = OutputSettings()
    output.print_filenames = args.print_filenames
    output.print_matches = args.print_matches
    output.save_to_directory = args.save

    if args.save is not None:
        os.makedirs(args.save, exist_ok=True)

    if args.yara:
        with open(args.yara, "r") as f:
            yara_rule = f.read()
        job_id = query(args.mquery, yara_rule)
    else:
        job_id = args.job

    process_job(args.mquery, job_id, output)


if __name__ == "__main__":
    main()
