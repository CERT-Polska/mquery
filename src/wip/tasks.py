from typing import Iterable, List, Any
import logging
import yara  # type: ignore
from lib.ursadb import Json
from lib.yaraparse import parse_yara, combine_rules
from schema import JobSchema
from wip.agent import Agent
import config
from rq import get_current_job
from db import Database, JobId
from redis import Redis
from rq import Queue
from contextlib import contextmanager


queue = Queue(connection=Redis(config.REDIS_HOST, config.REDIS_PORT))


@contextmanager
def job_context(job_id: JobId):
    agent = __make_agent()

    try:
        yield agent
    except Exception as e:
        logging.exception("Failed to execute %s.", job_id)
        agent.db.agent_finish_job(job_id)
        agent.db.fail_job(job_id, str(e))
        raise


def __make_agent():
    db = Database(config.REDIS_HOST, config.REDIS_PORT)
    group_id = get_current_job().origin
    return Agent(group_id, config.BACKEND, db)


def ursadb_command(command: str) -> Json:
    agent = __make_agent()
    json = agent.ursa.execute_command(command)
    return json


def start_search(job_id: JobId) -> None:
    with job_context(job_id) as agent:
        job = agent.db.get_job(job_id)
        if job.status == "cancelled":
            logging.info("Job was cancelled, returning...")
            return

        datasets = agent.get_datasets()
        logging.info("Datasets found: %s.", datasets)
        if not datasets:
            logging.info("No datasets found - cancelling the job.")
            agent.db.agent_finish_job(job_id)
            return

        rules = parse_yara(job.raw_yara)
        parsed = combine_rules(rules)
        logging.info("Will use the following query: %s", parsed.query)

        prev_job = None
        for dataset in datasets:
            # We add dependencies between all the jobs, to enforce sequential
            # execution. The goal is to avoid overwhelming ursadb with too
            # many queries.
            prev_job = queue.enqueue(
                query_ursadb,
                job_id,
                dataset,
                parsed.query,
                depends_on=prev_job
            )


def __get_batch_sizes(file_count: int) -> List[int]:
    """Returns a list of integers that sums to file_count. The idea is to split
    the work between all workers into units that are not too small and not
    too big. Currently just creates equally sized batches."""
    result = []
    BATCH_SIZE = 50
    while file_count > BATCH_SIZE:
        result.append(BATCH_SIZE)
        file_count -= BATCH_SIZE
    if file_count > 0:
        result.append(file_count)
    return result


def query_ursadb(job_id: JobId, dataset_id: str, ursadb_query: str) -> None:
    with job_context(job_id) as agent:
        job = agent.db.get_job(job_id)
        if job.status == "cancelled":
            logging.info("Job was cancelled, returning...")
            return

        result = agent.ursa.query(ursadb_query, job.taints, dataset_id)
        if "error" in result:
            raise RuntimeError(result["error"])

        file_count = result["file_count"]
        iterator = result["iterator"]
        logging.info(f"Iterator {iterator} contains {file_count} files")

        total_files = agent.db.update_job_files(job_id, file_count)
        if job.files_limit and total_files > job.files_limit:
            raise RuntimeError(
                f"Too many candidates after prefiltering (limit: {job.files_limit}). "
                "Try a more precise query."
            )

        # self.db.dataset_query_done(job_id)
        for batch in __get_batch_sizes(file_count):
            queue.enqueue(run_yara_batch, job_id, iterator, batch)

        # TODO this is obviously temporary, for debugging
        from time import sleep
        sleep(2)


def __execute_yara(agent: Agent, job: JobSchema, files: List[str]) -> None:
    rule = yara.compile(source=job.raw_yara)
    num_matches = 0
    num_errors = 0
    num_files = len(files)
    agent.db.job_start_work(JobId(job.id), num_files)

    # HACK this is obviously temporary
    rebase = "/mnt/samples/"
    rebase_to = "/home/msm/Projects/mquery/samples/"
    files = [rebase_to + file[len(rebase):] for file in files]

    filemap_raw = {name: agent.plugins.filter(name) for name in files}
    filemap = {k: v for k, v in filemap_raw.items() if v}

    for orig_name, path in filemap.items():
        try:
            matches = rule.match(path)
            if matches:
                agent.update_metadata(
                    JobId(job.id), orig_name, path, [r.rule for r in matches]
                )
                num_matches += 1
        except yara.Error:
            logging.error("Yara failed to check file %s", orig_name)
            num_errors += 1
        except FileNotFoundError:
            logging.error(
                "Failed to open file for yara check: %s", orig_name
            )
            num_errors += 1

    agent.plugins.cleanup()

    if num_errors > 0:
        agent.db.job_update_error(JobId(job.id), num_errors)

    agent.db.job_update_work(JobId(job.id), num_files, num_matches)


def run_yara_batch(job_id: JobId, iterator_id: str, batch_size: int) -> None:
    with job_context(job_id) as agent:
        job = agent.db.get_job(job_id)
        if job.status == "cancelled":
            logging.info("Job was cancelled, returning...")
            return

        pop_result = agent.ursa.pop(iterator_id, batch_size)
        logging.info("job %s: Ursadb pop successful: %s", job.id, pop_result)

        __execute_yara(agent, job, pop_result.files)

        # if self.db.job_yara_left(self.group_id, job) == 0:
        #     # The job is over, work of this agent as done.
        #     logging.info("job %s: No more files, agent finished.", job.hash)
        #     self.db.agent_finish_job(job)
