#!/usr/bin/env python
import logging
import yara  # type: ignore
import config
import json
import sys
from functools import lru_cache
from lib.ursadb import UrsaDb
from util import setup_logging
from typing import Any, List, Set
from lib.yaraparse import parse_yara, combine_rules
from db import AgentTask, JobId, Database, MatchInfo

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


def execute_search(agent_id: str, job_id: JobId) -> None:
    logging.info("Parsing...")

    job = db.get_job(job_id)
    if job.status == "cancelled":
        return

    rules = parse_yara(job.raw_yara)
    parsed = combine_rules(rules)

    logging.info("Querying backend...")
    result = ursa.query(parsed.query, job.taint)
    if "error" in result:
        raise RuntimeError(result["error"])

    file_count = result["file_count"]
    iterator = result["iterator"]
    logging.info(f"Iterator {iterator} contains {file_count} files")

    db.update_job_files(job_id, file_count)
    db.agent_start_job(agent_id, job_id, iterator)


def update_metadata(job: JobId, file_path: str, matches: List[str]) -> None:
    match = MatchInfo(file_path, {}, matches)
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
    num_matches = 0
    db.job_start_work(job, len(files))
    for sample in files:
        try:
            matches = rule.match(sample)
            if matches:
                num_matches += 1
                update_metadata(job, sample, [r.rule for r in matches])
        except yara.Error:
            logging.exception(f"Yara failed to check file {sample}")
        except FileNotFoundError:
            logging.exception(f"Failed to open file for yara check: {sample}")

    db.job_update_work(job, len(files), num_matches)


def do_search(job: JobId, iterator: str):
    try:
        BATCH_SIZE = 500
        pop_result = ursa.pop(iterator, BATCH_SIZE)
        if pop_result.was_locked:
            logging.info(
                "Iterator %s is locked, retrying in a second", iterator
            )
            return False
        if pop_result.files:
            execute_yara(job, pop_result.files)
        if pop_result.should_drop_iterator:
            logging.info(
                "Dropping job %s because iterator %s is empty",
                job.key,
                iterator,
            )
            return True
    except Exception:
        logging.exception("Failed to execute yara match.")
        return True
    return False


def process_task(
    agent_id: str, task: AgentTask, finished_jobs: Set[str]
) -> None:
    if task.type == "search":
        job = JobId(task.data)
        logging.info(f"New task: {job.hash}")

        try:
            execute_search(agent_id, job)
        except Exception:
            logging.exception("Failed to execute job.")
            db.agent_finish_job(agent_id, job)
    elif task.type == "yara":
        logging.info("yara task: %s", task.data)
        data = json.loads(task.data)
        job = JobId(data["job"])
        iterator = data["iterator"]
        if job.key in finished_jobs:
            return
        db.agent_start_job(agent_id, job, iterator)
        if do_search(job, iterator):
            finished_jobs.add(job.key)
            db.agent_finish_job(agent_id, job)
    else:
        raise RuntimeError("Unsupported quue")


def main() -> None:
    setup_logging()
    if len(sys.argv) > 1:
        agent_id = sys.argv[1]
    else:
        agent_id = "default"

    logging.info("Agent [%s] running...", agent_id)
    db.register_active_agent(agent_id)

    finished_jobs: Set[str] = set()
    while True:
        task = db.agent_get_task(agent_id)
        process_task(agent_id, task, finished_jobs)


if __name__ == "__main__":
    main()
