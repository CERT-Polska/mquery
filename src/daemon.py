#!/usr/bin/env python
import logging
import yara  # type: ignore
import config
import json
import sys
from lib.ursadb import UrsaDb
from util import setup_logging
from typing import Any, List
from lib.yaraparse import parse_yara, combine_rules
from db import AgentTask, JobId, Database, MatchInfo
from cachetools import cached, LRUCache


@cached(cache=LRUCache(maxsize=32), key=lambda db, job: job.key)
def compile_yara(db: Database, job: JobId) -> Any:
    """Gets a compiled yara rule belinging to the provided job. Uses cache
    to speed up compilation.

    :param job: ID of the job to compile yara for.
    :type job: JobId
    :raises SyntaxError: When yara rule has invalid syntax.
    :return: Compiled yara rule.
    :rtype: Any
    """
    yara_rule = db.get_yara_by_job(job)

    logging.info("Compiling Yara")
    try:
        rule = yara.compile(source=yara_rule)
    except SyntaxError as e:
        logging.exception("Yara parse error")
        raise e

    return rule


class Agent:
    def __init__(self, group_id: str, ursa_url: str, db: Database) -> None:
        """Creates a new agent instance. Every agents belongs to some group
        (identified by `group_id`). There may be multiple agents in a
        single group, but they're all exchangeable (they read and write to the
        same queues, and they use the same ursadb instance).

        :param group_id: Identifier of the agent group this agent belongs to.
        :type group_id: str
        :param ursa_url: URL to connected ursadb instance. Ideally this should
            be public, because this will allow mquery to collect measurements.
        :type ursa_url: str
        :param db: Reference to main database/task queue.
        :type db: Database
        """
        self.group_id = group_id
        self.ursa_url = ursa_url
        self.db = db
        self.ursa = UrsaDb(self.ursa_url)

    def __search_task(self, job_id: JobId) -> None:
        """Do ursadb query for yara belonging to the provided job.
        If successful, create a new yara tasks to do further processing
        of the results.
        """
        logging.info("Parsing...")

        job = self.db.get_job(job_id)
        if job.status == "cancelled":
            return

        rules = parse_yara(job.raw_yara)
        parsed = combine_rules(rules)

        logging.info("Querying backend...")
        result = self.ursa.query(parsed.query, job.taint)
        if "error" in result:
            raise RuntimeError(result["error"])

        file_count = result["file_count"]
        iterator = result["iterator"]
        logging.info(f"Iterator {iterator} contains {file_count} files")

        self.db.update_job_files(job_id, file_count)
        self.db.agent_start_job(self.group_id, job_id, iterator)

    def __update_metadata(
        self, job: JobId, file_path: str, matches: List[str]
    ) -> None:
        """ After finding a match, push it into a database and
        update the related metadata """
        match = MatchInfo(file_path, {}, matches)
        self.db.add_match(job, match)

    def __execute_yara(self, job: JobId, files: List[str]) -> None:
        rule = compile_yara(self.db, job)
        num_matches = 0
        self.db.job_start_work(job, len(files))
        for sample in files:
            try:
                matches = rule.match(sample)
                if matches:
                    num_matches += 1
                    self.__update_metadata(
                        job, sample, [r.rule for r in matches]
                    )
            except yara.Error:
                logging.exception(f"Yara failed to check file {sample}")
            except FileNotFoundError:
                logging.exception(
                    f"Failed to open file for yara check: {sample}"
                )

        self.db.job_update_work(job, len(files), num_matches)

    def __yara_task(self, job: JobId, iterator: str) -> None:
        """Get a next batch of worm from the db. If there are still files
        left in the iterator, push the task back to the same queue (so
        that other agents will be able to work on it in parallel). Later,
        process the obtained files.
        """
        final_statuses = ["cancelled", "failed", "done"]
        if self.db.get_job_status(job) in final_statuses:
            return

        BATCH_SIZE = 500
        pop_result = self.ursa.pop(iterator, BATCH_SIZE)
        if not pop_result.iterator_empty:
            # The job still have some files, put it back on the queue.
            self.db.agent_start_job(self.group_id, job, iterator)
        if pop_result.files:
            # If there are any files popped iterator, work on them
            self.__execute_yara(job, pop_result.files)

        j = self.db.get_job(job)
        if j.status == "processing" and j.files_processed == j.total_files:
            # The job is over, work of this agent as done.
            self.db.agent_finish_job(job)

    def __process_task(self, task: AgentTask) -> None:
        """Dispatches and executes the next incoming task.

        The high level workflow look like this: for every new `search` job,
        mquery creates a new `search` task for every agent group.
        One of the agents will pick it up and execute, and create `yara`
        tasks. `yara` tasks will be executed by workers for every file in
        iterator, until it's exhausted.

        :param task: Task to be executed.
        :type task: AgentTask
        :raises RuntimeError: Task with unsupported type given.
        """
        if task.type == "search":
            job = JobId(task.data)
            logging.info(f"search: {job.hash}")

            try:
                self.__search_task(job)
            except Exception as e:
                logging.exception("Failed to execute task.")
                self.db.fail_job(job, str(e))
                self.db.agent_finish_job(job)
        elif task.type == "yara":
            data = json.loads(task.data)
            job = JobId(data["job"])
            iterator = data["iterator"]
            logging.info("yara: iterator %s", iterator)

            try:
                self.__yara_task(job, iterator)
            except Exception as e:
                logging.exception("Failed to execute task.")
                self.db.fail_job(job, str(e))
                self.db.agent_finish_job(job)
        else:
            raise RuntimeError("Unsupported queue")

    def main_loop(self) -> None:
        """Starts a main loop of the agent - this is the only intended public
        method of this class. This will register the agent in the db, then pop
        tasks from redis as they come, and execute them.
        """
        self.db.register_active_agent(self.group_id, self.ursa_url)

        while True:
            task = self.db.agent_get_task(self.group_id)
            self.__process_task(task)


def main() -> None:
    """Spawns a new agent process. Use argv if you want to use a different
    group_id (it's `default` by default)
    """
    setup_logging()
    if len(sys.argv) > 1:
        agent_group_id = sys.argv[1]
    else:
        agent_group_id = "default"

    logging.info("Agent [%s] running...", agent_group_id)

    db = Database(config.REDIS_HOST, config.REDIS_PORT)
    agent = Agent(agent_group_id, config.BACKEND, db)

    agent.main_loop()


if __name__ == "__main__":
    main()
