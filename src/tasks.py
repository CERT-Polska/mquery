import base64
from typing import List, Optional, cast, Dict
import logging
from rq import get_current_job, Queue  # type: ignore
from redis import Redis
from contextlib import contextmanager
import yara  # type: ignore

from .db import Database, JobId
from .util import make_sha256_tag
from .config import app_config
from .plugins import PluginManager
from .models.job import Job, JobStatus
from .models.match import Match
from .lib.yaraparse import parse_yara, combine_rules
from .lib.ursadb import Json, UrsaDb
from .metadata import Metadata


class Agent:
    def __init__(self, group_id: str) -> None:
        """Creates a new agent instance. Every agents belongs to some group
        (identified by the group_id). There may be multiple agent workers in a
        single group, but they must all work on the same ursadb instance.
        Reads connection parameters and plugins from the global config.
        """
        self.group_id = group_id
        self.ursa_url = app_config.mquery.backend
        self.__db_object = None  # set before starting first task
        self.db = Database(app_config.redis.host, app_config.redis.port)
        self.ursa = UrsaDb(self.ursa_url)
        self.plugins = PluginManager(app_config.mquery.plugins, self.db)
        self.queue = Queue(
            group_id,
            connection=Redis(app_config.redis.host, app_config.redis.port),
        )

    @property
    def db_id(self):
        if self.__db_object is None:
            self.__db_object = self.db.get_active_agents()[self.group_id]
        return cast(int, self.__db_object.id)

    def register(self) -> None:
        """Register the agent in the database. Should happen when starting
        the worker process.
        """
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
        self,
        job: JobId,
        orig_name: str,
        path: str,
        matches: List[str],
        context: Dict[str, Dict[str, Dict[str, str]]],
    ) -> None:
        """Saves matches to the database, and runs appropriate metadata
        plugins.
        """

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
        match = Match(
            file=orig_name, meta=metadata, matches=matches, context=context
        )
        self.db.add_match(job, match)

    def execute_yara(self, job: Job, files: List[str]) -> None:
        rule = yara.compile(source=job.raw_yara)
        num_matches = 0
        num_errors = 0
        num_files = len(files)
        self.db.job_start_work(job.id, num_files)

        for orig_name in files:
            try:
                path = self.plugins.filter(orig_name)
                if not path:
                    continue

                matches = rule.match(path)
                if matches:
                    with open(path, "rb") as file:
                        data = file.read()

                    self.update_metadata(
                        job.id,
                        orig_name,
                        path,
                        [r.rule for r in matches],
                        get_match_contexts(data, matches),
                    )
                    num_matches += 1
            except yara.Error:
                logging.error("Yara failed to check file %s", orig_name)
                num_errors += 1
            except FileNotFoundError:
                logging.error("Failed to open file %s", orig_name)
                num_errors += 1
            except Exception:
                logging.exception("Unknown error (plugin?): %s", orig_name)
                num_errors += 1

        self.plugins.cleanup()
        new_processed = self.db.job_update_work(
            job.id, num_files, num_matches, num_errors
        )
        yara_limit = app_config.mquery.yara_limit
        if yara_limit != 0 and new_processed > yara_limit:
            scan_percent = new_processed / job.total_files
            scanned_datasets = job.total_datasets - job.datasets_left
            dataset_percent = scanned_datasets / job.total_datasets
            self.db.fail_job(
                job.id,
                f"Configured limit of {yara_limit} YARA matches exceeded. "
                f"Scanned {new_processed}/{job.total_files} ({scan_percent:.0%}) of candidates "
                f"in {scanned_datasets}/{job.total_datasets} ({dataset_percent:.0%}) of datasets.",
            )

    def init_search(self, job: Job, tasks: int) -> None:
        self.db.init_jobagent(job, self.db_id, tasks)

    def add_tasks_in_progress(self, job: Job, tasks: int) -> None:
        """See documentation of db.agent_add_tasks_in_progress."""
        self.db.agent_add_tasks_in_progress(job, self.db_id, tasks)


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
        group_id = get_current_job().origin  # type: ignore
    return Agent(group_id)


def ursadb_command(command: str) -> Json:
    """Executes a raw ursadb command using this backend."""
    agent = make_agent()
    json = agent.ursa.execute_command(command)
    return json


def start_search(job_id: JobId) -> None:
    """Initialises a search task - checks available datasets and schedules smaller
    units of work.
    """
    with job_context(job_id) as agent:
        job = agent.db.get_job(job_id)
        if job.status == JobStatus.cancelled:
            logging.info("Job was cancelled, returning...")
            return

        datasets = agent.get_datasets()
        agent.db.init_job_datasets(job_id, len(datasets))

        # Sets the number of datasets in progress.
        # Caveat: if no datasets, this call is still important, because it
        # will let the db know that this agent has nothing more to do.
        agent.init_search(job, len(datasets))

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
                job_timeout=app_config.rq.job_timeout,
            )


def __get_batch_sizes(file_count: int) -> List[int]:
    """Returns a list of integers that sums to file_count. The idea is to split
    the work between all workers into units that are not too small and not
    too big. Currently just creates equally sized batches.
    """
    result = []
    BATCH_SIZE = 50
    while file_count > BATCH_SIZE:
        result.append(BATCH_SIZE)
        file_count -= BATCH_SIZE
    if file_count > 0:
        result.append(file_count)
    return result


def query_ursadb(job_id: JobId, dataset_id: str, ursadb_query: str) -> None:
    """Queries ursadb and creates yara scans tasks with file batches."""
    with job_context(job_id) as agent:
        job = agent.db.get_job(job_id)
        if job.status == JobStatus.cancelled:
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
        # add len(batches) new tasks, -1 to account for this task
        agent.add_tasks_in_progress(job, len(batches) - 1)

        for batch in batches:
            agent.queue.enqueue(
                run_yara_batch,
                job_id,
                iterator,
                batch,
                job_timeout=app_config.rq.job_timeout,
            )

        agent.db.dataset_query_done(job_id)


def run_yara_batch(job_id: JobId, iterator: str, batch_size: int) -> None:
    """Actually scans files, and updates a database with the results."""
    with job_context(job_id) as agent:
        job = agent.db.get_job(job_id)
        if job.status == JobStatus.cancelled:
            logging.info("Job was cancelled, returning...")
            return

        pop_result = agent.ursa.pop(iterator, batch_size)
        logging.info("job %s: Pop successful: %s", job_id, pop_result)
        if pop_result.was_locked:
            # Iterator is currently locked, re-enqueue self
            agent.queue.enqueue(
                run_yara_batch,
                job_id,
                iterator,
                batch_size,
                job_timeout=app_config.rq.job_timeout,
            )
            return

        agent.execute_yara(job, pop_result.files)
        agent.add_tasks_in_progress(job, -1)


def get_match_contexts(
    data: bytes, matches: List[yara.Match]
) -> Dict[str, Dict[str, Dict[str, str]]]:
    context = {}
    for yara_match in matches:
        match_context = {}
        for string_match in yara_match.strings:
            first = string_match.instances[0]

            (before, matching, after) = read_bytes_with_context(
                data, first.offset, first.matched_length
            )
            match_context[string_match.identifier] = {
                "before": base64.b64encode(before).decode("utf-8"),
                "matching": base64.b64encode(matching).decode("utf-8"),
                "after": base64.b64encode(after).decode("utf-8"),
            }

            context[yara_match.rule] = match_context
    return context


def read_bytes_with_context(
    data: bytes, offset: int, length: int, context: int = 32
) -> tuple[bytes, bytes, bytes]:
    """Return `matched_length` bytes from `offset`, along with `byte_range` bytes before and after the match."""
    before = data[max(0, offset - context) : offset]
    matching = data[offset : offset + length]
    after = data[offset + length : offset + length + context]
    return before, matching, after
