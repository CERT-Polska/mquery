from typing import List, Optional
import logging
from lib.ursadb import Json, UrsaDb
from schema import JobSchema
from lib.yaraparse import parse_yara, combine_rules
from plugins import PluginManager
import config
from rq import get_current_job, Queue  # type: ignore
from db import Database, JobId, MatchInfo
from redis import Redis
from contextlib import contextmanager
from util import make_sha256_tag
from metadata import Metadata
import yara  # type: ignore


class Agent:
    def __init__(self, group_id: str) -> None:
        """Creates a new agent instance. Every agents belongs to some group
        (identified by the group_id). There may be multiple agent workers in a
        single group, but they must all work on the same ursadb instance.
        Reads connection parameters and plugins from the global config."""
        self.group_id = group_id
        self.ursa_url = config.BACKEND
        self.db = Database(config.REDIS_HOST, config.REDIS_PORT)
        self.ursa = UrsaDb(self.ursa_url)
        self.plugins = PluginManager(config.PLUGINS, self.db)
        self.queue = Queue(
            group_id, connection=Redis(config.REDIS_HOST, config.REDIS_PORT)
        )

    def register(self) -> None:
        """Register the plugin in the database. Should happen when starting
        the worker process."""
        plugins_spec = {
            plugin_class.get_name(): plugin_class.config_fields
            for plugin_class in self.plugins.plugin_classes
        }
        self.db.register_active_agent(
            self.group_id,
            self.ursa_url,
            plugins_spec,
            [
                active_plugin.get_name()
                for active_plugin in self.plugins.active_plugins
            ],
        )

    def get_datasets(self) -> List[str]:
        """Returns a list of dataset IDs, or throws an exception on error."""
        result = self.ursa.topology()

        if "error" in result:
            raise RuntimeError(result["error"])

        return list(result["result"]["datasets"].keys())

    def update_metadata(
        self, job: JobId, orig_name: str, path: str, matches: List[str]
    ) -> None:
        """Saves matches to the database, and runs appropriate metadata
        plugins."""

        # Initialise default values in the metadata.
        metadata: Metadata = {
            "job": job,
            "path": path,
            "sha256": make_sha256_tag(path),
        }
        # Run all the plugins in configured order.
        for plugin in self.plugins.active_plugins:
            if not plugin.is_extractor:
                continue

            extracted_meta = plugin.run(orig_name, metadata)
            metadata.update(extracted_meta)

        # Remove unnecessary keys from the metadata.
        del metadata["job"]
        del metadata["path"]

        # Update the database.
        match = MatchInfo(orig_name, metadata, matches)
        self.db.add_match(job, match)

    def execute_yara(self, job: JobSchema, files: List[str]) -> None:
        rule = yara.compile(source=job.raw_yara)
        num_matches = 0
        num_errors = 0
        num_files = len(files)
        self.db.job_start_work(job.id, num_files)

        filemap_raw = {name: self.plugins.filter(name) for name in files}
        filemap = {k: v for k, v in filemap_raw.items() if v}

        for orig_name, path in filemap.items():
            try:
                matches = rule.match(path)
                if matches:
                    self.update_metadata(
                        job.id, orig_name, path, [r.rule for r in matches]
                    )
                    num_matches += 1
            except yara.Error:
                logging.error("Yara failed to check file %s", orig_name)
                num_errors += 1
            except FileNotFoundError:
                logging.error("Failed to open file %s", orig_name)
                num_errors += 1

        self.plugins.cleanup()
        self.db.job_update_work(job.id, num_files, num_matches, num_errors)

    def add_tasks_in_progress(self, job: JobSchema, tasks: int) -> None:
        """See documentation of db.agent_add_tasks_in_progress"""
        self.db.agent_add_tasks_in_progress(job.id, self.group_id, tasks)


@contextmanager
def job_context(job_id: JobId):
    """Small error-handling context manager. Fails the job on exception."""
    agent = make_agent()
    try:
        yield agent
    except Exception as e:
        logging.exception("Failed to execute %s.", job_id)
        agent.db.fail_job(job_id, str(e))
        raise


def make_agent(group_override: Optional[str] = None):
    """Creates a new agent using the default settings from config."""
    if group_override is not None:
        group_id = group_override
    else:
        group_id = get_current_job().origin
    return Agent(group_id)


def ursadb_command(command: str) -> Json:
    """Executes a raw ursadb command using this backend."""
    agent = make_agent()
    json = agent.ursa.execute_command(command)
    return json


def start_search(job_id: JobId) -> None:
    """Initialises a search task - checks available datasets and schedules smaller
    units of work."""
    with job_context(job_id) as agent:
        job = agent.db.get_job(job_id)
        if job.status == "cancelled":
            logging.info("Job was cancelled, returning...")
            return

        datasets = agent.get_datasets()
        agent.db.init_job_datasets(job_id, len(datasets))

        # Caveat: if no datasets, this call is still important, because it
        # will let the db know that this agent has nothing more to do.
        agent.add_tasks_in_progress(job, len(datasets))

        rules = parse_yara(job.raw_yara)
        parsed = combine_rules(rules)
        logging.info("Will use the following query: %s", parsed.query)

        prev_job = None
        for dataset in datasets:
            # We add dependencies between all the jobs, to enforce sequential
            # execution. The goal is to avoid overwhelming ursadb with too
            # many queries.
            prev_job = agent.queue.enqueue(
                query_ursadb,
                job_id,
                dataset,
                parsed.query,
                depends_on=prev_job,
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
    """Queries ursadb and creates yara scans tasks with file batches"""
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

        batches = __get_batch_sizes(file_count)
        for batch in batches:
            agent.queue.enqueue(run_yara_batch, job_id, iterator, batch)

        agent.db.dataset_query_done(job_id)

        # add len(batches) new tasks, -1 to account for this task
        agent.add_tasks_in_progress(job, len(batches) - 1)


def run_yara_batch(job_id: JobId, iterator: str, batch_size: int) -> None:
    """Actually scans files, and updates a database with the results"""
    with job_context(job_id) as agent:
        job = agent.db.get_job(job_id)
        if job.status == "cancelled":
            logging.info("Job was cancelled, returning...")
            return

        pop_result = agent.ursa.pop(iterator, batch_size)
        logging.info("job %s: Pop successful: %s", job_id, pop_result)
        if pop_result.was_locked:
            # Iterator is currently locked, re-enqueue self
            agent.queue.enqueue(run_yara_batch, job_id, iterator, batch_size)
            return

        agent.execute_yara(job, pop_result.files)
        agent.add_tasks_in_progress(job, -1)
