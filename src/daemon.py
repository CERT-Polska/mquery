#!/usr/bin/env python
import json
import logging
import time
import yara  # type: ignore
from functools import lru_cache
import random
from yara import SyntaxError
import config
from lib.ursadb import UrsaDb
from lib.yaraparse import parse_yara, combine_rules
from util import make_redis, setup_logging
from typing import Any, Dict, List, Optional, Tuple

redis = make_redis()
db = UrsaDb(config.BACKEND)


@lru_cache(maxsize=32)
def compile_yara(job_hash: str) -> Any:
    yara_rule = redis.hget("job:" + job_hash, "raw_yara")

    logging.info("Compiling Yara")
    try:
        rule = yara.compile(source=yara_rule)
    except SyntaxError as e:
        logging.exception("Yara parse error")
        raise e

    return rule


def get_list_name(priority: str) -> str:
    if priority == "low":
        return "list-yara-low"
    elif priority == "medium":
        return "list-yara-medium"
    else:
        return "list-yara-high"


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


def process_task(queue: str, data: str) -> None:
    if queue == "queue-search":
        job_hash = data
        logging.info(f"New task: {queue}:{job_hash}")

        try:
            execute_search(job_hash)
        except Exception as e:
            logging.exception("Failed to execute job.")
            redis.hmset(
                "job:" + job_hash, {"status": "failed", "error": str(e)}
            )
    elif queue == "queue-commands":
        logging.info("Running a command: %s", data)
        resp = db.execute_command(data)
        logging.info(resp)


def get_random_job_by_priority() -> Tuple[Optional[str], str]:
    yara_lists = ["list-yara-high", "list-yara-medium", "list-yara-low"]
    for yara_list in yara_lists:
        yara_jobs = redis.lrange(yara_list, 0, -1)
        if yara_jobs:
            return yara_list, random.choice(yara_jobs)
    return None, ""


def try_to_do_task() -> bool:
    task_queues = ["queue-search", "queue-commands"]
    task = None
    for queue in task_queues:
        task = redis.lpop(queue)
        if task is not None:
            data = task
            process_task(queue, data)
            return True

    return False


def try_to_do_search() -> bool:
    yara_list, job_hash = get_random_job_by_priority()
    if yara_list is None:
        return False

    job_id = "job:" + job_hash
    job_data = redis.hgetall(job_id)

    try:
        BATCH_SIZE = 500
        ready, files = db.pop(job_data["iterator"], BATCH_SIZE)
        if not ready:
            # iterator locked, try again later
            return True
        execute_yara(job_hash, files)
        if len(files) < BATCH_SIZE:
            redis.hset(job_id, "status", "done")
            redis.lrem(yara_list, 0, job_hash)
    except Exception as e:
        logging.exception("Failed to execute yara match.")
        redis.hmset(job_id, {"status": "failed", "error": str(e)})
        redis.lrem(yara_list, 0, job_hash)
    return True


def job_daemon() -> None:
    setup_logging()
    logging.info("Daemon running...")

    for extractor in config.METADATA_EXTRACTORS:
        logging.info("Plugin loaded: %s", extractor.__class__.__name__)
        extractor.set_redis(redis)

    logging.info("Daemon loaded, entering the main loop...")

    while True:
        if try_to_do_task():
            continue

        if try_to_do_search():
            continue

        if redis.set("gc-lock", "locked", ex=60, nx=True):
            collect_expired_jobs()

        time.sleep(5)


def update_metadata(job_hash: str, file_path: str, matches: List[str]) -> None:
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

        local_meta.update(job=job_hash)
        current_meta[extr_name] = extractor.extract(file_path, local_meta)

    # flatten
    flat_meta: Dict[str, Any] = {}

    for v in current_meta.values():
        flat_meta.update(v)

    redis.rpush(
        "meta:{}".format(job_hash),
        json.dumps({"file": file_path, "meta": flat_meta, "matches": matches}),
    )


def execute_yara(job_hash: str, files: List[str]) -> None:
    job_id = f"job:{job_hash}"
    if redis.hget(job_id, "status") in [
        "cancelled",
        "failed",
    ]:
        return

    if len(files) == 0:
        return

    rule = compile_yara(job_hash)

    for sample in files:
        try:
            matches = rule.match(data=open(sample, "rb").read())
            if matches:
                update_metadata(job_hash, sample, [r.rule for r in matches])
        except yara.Error:
            logging.exception(f"Yara failed to check file {sample}")
        except FileNotFoundError:
            logging.exception(f"Failed to open file for yara check: {sample}")

    redis.hincrby(job_id, "files_processed", len(files))


def execute_search(job_hash: str) -> None:
    logging.info("Parsing...")
    job_id = "job:" + job_hash

    job = redis.hgetall(job_id)
    yara_rule = job["raw_yara"]

    redis.hmset(job_id, {"status": "parsing", "timestamp": time.time()})

    rules = parse_yara(yara_rule)
    parsed = combine_rules(rules)

    redis.hmset(job_id, {"status": "querying", "timestamp": time.time()})

    logging.info("Querying backend...")
    taint = job.get("taint", None)
    result = db.query(parsed.query, taint)
    if "error" in result:
        raise RuntimeError(result["error"])

    file_count = result["file_count"]
    iterator = result["iterator"]
    logging.info(f"Iterator contains {file_count} files")

    redis.hmset(
        job_id,
        {
            "status": "processing",
            "iterator": iterator,
            "files_processed": 0,
            "total_files": file_count,
        },
    )

    if file_count > 0:
        list_name = get_list_name(job["priority"])
        redis.lpush(list_name, job_hash)
    else:
        redis.hset(job_id, "status", "done")


if __name__ == "__main__":
    job_daemon()
