#!/usr/bin/env python
import logging
import time
import yara  # type: ignore
from functools import lru_cache
from yara import SyntaxError
import config
from lib.ursadb import UrsaDb
from lib.yaraparse import parse_yara, combine_rules
from util import setup_logging
from typing import Any, Dict, List
from db import Database, JobId, MatchInfo

db = Database()
ursa = UrsaDb(config.BACKEND)


@lru_cache(maxsize=32)
def compile_yara(job: JobId) -> Any:
    yara_rule = db.get_yara_by_job(job)

    logging.info("Compiling Yara")
    try:
        rule = yara.compile(source=yara_rule)
    except SyntaxError as e:
        logging.exception("Yara parse error")
        raise e

    return rule


def collect_expired_jobs() -> None:
    if config.JOB_EXPIRATION_MINUTES <= 0:
        return

    exp_time = int(60 * config.JOB_EXPIRATION_MINUTES)  # conversion to seconds

    for job in db.get_job_ids():
        job_submission_time = db.get_job_submitted(job)
        if (int(time.time()) - job_submission_time) >= exp_time:
            db.expire_job(job)


def process_task(queue: str, data: str) -> None:
    if queue == "queue-search":
        job = JobId(data)
        logging.info(f"New task: {queue}:{job.hash}")

        try:
            execute_search(job)
        except Exception as e:
            logging.exception("Failed to execute job.")
            db.fail_job(None, job, str(e))
    elif queue == "queue-commands":
        logging.info("Running a command: %s", data)
        resp = ursa.execute_command(data)
        logging.info(resp)


def try_to_do_task() -> bool:
    queue_and_task = db.get_task()
    if queue_and_task is not None:
        queue, task = queue_and_task
        process_task(queue, task)
        return True

    return False


def try_to_do_search() -> bool:
    rnd_job = db.get_random_job_by_priority()
    if rnd_job is None:
        return False
    yara_list, job = rnd_job
    job_data = db.get_job(job)

    try:
        BATCH_SIZE = 500
        if job_data.iterator is None:
            raise RuntimeError(f"Job {job} has no iterator")
        pop_result = ursa.pop(job_data.iterator, BATCH_SIZE)
        if pop_result.was_locked:
            return True
        if pop_result.files:
            execute_yara(job, pop_result.files)
        if pop_result.should_drop_iterator:
            logging.info(
                "Iterator %s exhausted, removing job %s",
                job_data.iterator,
                job,
            )
            db.finish_job(yara_list, job)
    except Exception as e:
        logging.exception("Failed to execute yara match.")
        db.fail_job(yara_list, job, str(e))
    return True


def job_daemon() -> None:
    setup_logging()
    logging.info("Daemon running...")

    for extractor in config.METADATA_EXTRACTORS:
        logging.info("Plugin loaded: %s", extractor.__class__.__name__)
        extractor.set_redis(db.unsafe_get_redis())

    logging.info("Daemon loaded, entering the main loop...")

    while True:
        if try_to_do_task():
            continue

        if try_to_do_search():
            continue

        if db.gc_lock():
            collect_expired_jobs()

        time.sleep(5)


def update_metadata(job: JobId, file_path: str, matches: List[str]) -> None:
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

        local_meta.update(job=job.hash)
        current_meta[extr_name] = extractor.extract(file_path, local_meta)

    # flatten
    flat_meta: Dict[str, Any] = {}

    for v in current_meta.values():
        flat_meta.update(v)

    match = MatchInfo(file_path, flat_meta, matches)
    db.add_match(job, match)


def execute_yara(job: JobId, files: List[str]) -> None:
    if db.get_job_status(job) in [
        "cancelled",
        "failed",
    ]:
        return

    if len(files) == 0:
        return

    rule = compile_yara(job)
    len_matches = 0
    for sample in files:
        try:
            matches = rule.match(sample)
            if matches:
                len_matches += 1
                update_metadata(job, sample, [r.rule for r in matches])
        except yara.Error:
            logging.exception(f"Yara failed to check file {sample}")
        except FileNotFoundError:
            logging.exception(f"Failed to open file for yara check: {sample}")

    db.update_job(job, len(files), len_matches)


def execute_search(job_id: JobId) -> None:
    logging.info("Parsing...")

    job = db.get_job(job_id)
    yara_rule = job.raw_yara

    db.set_job_to_parsing(job_id)

    rules = parse_yara(yara_rule)
    parsed = combine_rules(rules)

    db.set_job_to_querying(job_id)

    logging.info("Querying backend...")
    result = ursa.query(parsed.query, job.taint)
    if "error" in result:
        raise RuntimeError(result["error"])

    file_count = result["file_count"]
    iterator = result["iterator"]
    logging.info(f"Iterator contains {file_count} files")

    db.set_job_to_processing(job_id, iterator, file_count)

    if file_count > 0:
        db.push_job_to_queue(job)
    else:
        db.finish_job(None, job_id)


if __name__ == "__main__":
    job_daemon()
