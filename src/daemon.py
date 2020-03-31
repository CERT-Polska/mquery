#!/usr/bin/env python
import json
import logging
import time

import yara  # type: ignore
from functools import lru_cache

from yara import SyntaxError

import config
from lib.ursadb import UrsaDb
from lib.yaraparse import parse_string
from util import make_redis, setup_logging
from typing import Any, Dict

redis = make_redis()
db = UrsaDb(config.BACKEND)


@lru_cache(maxsize=8)
def compile_yara(job_hash: str) -> Any:
    yara_rule = redis.hget("job:" + job_hash, "raw_yara")

    logging.info("Compiling Yara")
    try:
        rule = yara.compile(source=yara_rule)
    except SyntaxError as e:
        logging.exception("Yara parse error")
        raise e

    return rule


def get_queue_name(priority: str) -> str:
    if priority == "low":
        return "queue-yara-low"
    elif priority == "medium":
        return "queue-yara-medium"
    else:
        return "queue-yara-high"


def collect_expired_jobs() -> None:
    exp_time = int(60 * config.JOB_EXPIRATION_MINUTES)  # conversion to seconds
    job_hashes = []

    for job_hash in redis.keys("job:*"):
        job_hashes.append(job_hash[4:])

    for job in job_hashes:
        redis.set("gc-lock", "locked", ex=60)
        job_submitted_time = int(redis.hget("job:" + job, "submitted"))
        if (int(time.time()) - job_submitted_time) >= exp_time:
            redis.hset("job:{}".format(job), "status", "expired")
            redis.delete("meta:{}".format(job))
            redis.delete("false_positives:{}".format(job))


def job_daemon() -> None:
    setup_logging()
    logging.info("Daemon running...")
    yara_queues = ["queue-yara-high", "queue-yara-medium", "queue-yara-low"]

    for extractor in config.METADATA_EXTRACTORS:
        logging.info("Plugin loaded: %s", extractor.__class__.__name__)
        extractor.set_redis(redis)

    logging.info("Daemon loaded, entering the main loop...")

    while True:
        queue, data = redis.blpop(
            ["queue-search", "queue-index", "queue-metadata", "queue-commands"]
            + yara_queues
        )

        if queue == "queue-search":
            job_hash = data
            logging.info("New task: {}:{}".format(queue, job_hash))

            try:
                execute_search(job_hash)
            except Exception as e:
                logging.exception("Failed to execute job.")
                redis.hmset(
                    "job:" + job_hash, {"status": "failed", "error": str(e)}
                )

        elif queue in yara_queues:
            job_hash, file_path = data.split(":", 1)
            try:
                execute_yara(job_hash, file_path)
            except Exception as e:
                logging.exception("Failed to execute yara match.")
                redis.hmset(
                    "job:" + job_hash, {"status": "failed", "error": str(e)}
                )

        elif queue == "queue-metadata":
            job_hash, file_path = data.split(":", 1)
            execute_metadata(job_hash, file_path)

        elif queue == "queue-commands":
            logging.info("Running a command: %s", data)
            resp = db.execute_command(data)
            logging.info(resp)

        if redis.set("gc-lock", "locked", ex=60, nx=True):
            collect_expired_jobs()


def execute_metadata(job_hash: str, file_path: str) -> None:
    if redis.hget("job:" + job_hash, "status") in [
        "cancelled",
        "failed",
    ]:
        return

    current_meta: Dict[str, Any] = {}

    for extractor in config.METADATA_EXTRACTORS:
        extr_name = extractor.__class__.__name__
        local_meta: Dict[str, Any] = {}
        deps = extractor.__depends_on__

        for dep in deps:
            if dep not in current_meta:
                raise RuntimeError(
                    "Configuration problem {} depends on {} but is declared earlier in config.".format(
                        extr_name, dep
                    )
                )

            # we build local dictionary for each extractor, thus enforcing dependencies to be declared correctly
            local_meta.update(current_meta[dep])

        current_meta[extr_name] = extractor.extract(file_path, local_meta)

    # flatten
    flat_meta: Dict[str, Any] = {}

    for v in current_meta.values():
        flat_meta.update(v)

    logging.info("Fetched metadata: " + file_path)

    pipe = redis.pipeline()
    pipe.rpush(
        "meta:{}".format(job_hash),
        json.dumps({"file": file_path, "meta": flat_meta}),
    )
    pipe.hget("job:{}".format(job_hash), "total_files")
    pipe.hincrby("job:{}".format(job_hash), "files_processed")
    _, total_files, files_processed = pipe.execute()

    if int(files_processed) >= int(total_files):
        redis.hset("job:{}".format(job_hash), "status", "done")


def execute_yara(job_hash: str, file: str) -> None:
    if redis.hget("job:" + job_hash, "status") in [
        "cancelled",
        "failed",
    ]:
        return

    rule = compile_yara(job_hash)

    try:
        matches = rule.match(data=open(file, "rb").read())
    except yara.Error:
        logging.exception("Yara failed to check file {}".format(file))
        matches = None
    except FileNotFoundError:
        logging.exception(
            "Failed to open file for yara check: {}".format(file)
        )
        matches = None

    if matches:
        logging.info("Processed (match): {}".format(file))
        redis.rpush("queue-metadata", "{}:{}".format(job_hash, file))
    else:
        logging.info("Processed (nope ): {}".format(file))

        pipe = redis.pipeline()
        pipe.rpush("false_positives:" + job_hash, file)
        pipe.hget("job:{}".format(job_hash), "total_files")
        pipe.hincrby("job:{}".format(job_hash), "files_processed")
        _, total_files, files_processed = pipe.execute()

        if int(files_processed) >= int(total_files):
            redis.hset("job:{}".format(job_hash), "status", "done")


def execute_search(job_hash: str) -> None:
    logging.info("Parsing...")

    job = redis.hgetall("job:" + job_hash)
    yara_rule = job["raw_yara"]

    redis.hmset(
        "job:" + job_hash, {"status": "parsing", "timestamp": time.time()}
    )

    try:
        parsed = parse_string(yara_rule)
    except Exception as e:
        logging.exception(e)
        raise RuntimeError("Failed to parse Yara")

    redis.hmset(
        "job:" + job_hash, {"status": "querying", "timestamp": time.time()}
    )

    logging.info("Querying backend...")
    result = db.query(parsed)
    if "error" in result:
        raise RuntimeError(result["error"])

    files = [f for f in result["files"] if f.strip()]

    logging.info("Database responded with {} files".format(len(files)))

    if "max_files" in job and int(job["max_files"]) > 0:
        files = files[: int(job["max_files"])]

    redis.hmset(
        "job:" + job_hash,
        {
            "status": "processing",
            "files_processed": 0,
            "total_files": len(files),
        },
    )

    if files:
        pipe = redis.pipeline()
        queue_name = get_queue_name(job["priority"])
        for file in files:
            if not config.SKIP_YARA:
                pipe.rpush(queue_name, "{}:{}".format(job_hash, file))
            else:
                pipe.rpush("queue-metadata", "{}:{}".format(job_hash, file))

        pipe.execute()
        logging.info("Done uploading yara jobs.")

    else:
        redis.hset("job:{}".format(job_hash), "status", "done")


if __name__ == "__main__":
    job_daemon()
