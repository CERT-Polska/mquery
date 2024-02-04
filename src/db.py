from collections import defaultdict
from typing import List, Optional, Dict, Any
from time import time
import json
import random
import string
from redis import StrictRedis
from enum import Enum
from rq import Queue  # type: ignore
from sqlmodel import Session, SQLModel, create_engine, select, and_, update

from .models.configentry import ConfigEntry
from .models.job import Job
from .schema import MatchesSchema, AgentSpecSchema, ConfigSchema
from .config import app_config


# "Magic" plugin name, used for configuration of mquery itself
MQUERY_PLUGIN_NAME = "Mquery"


class TaskType(Enum):
    SEARCH = "search"
    YARA = "yara"
    RELOAD = "reload"
    COMMAND = "command"


class AgentTask:
    def __init__(self, type: TaskType, data: str):
        self.type = type
        self.data = data


# Type alias for Job ids
JobId = str


class MatchInfo:
    """Represents information about a single match"""

    def __init__(
        self, file: str, meta: Dict[str, Any], matches: List[str]
    ) -> None:
        self.file = file
        self.meta = meta
        self.matches = matches

    def to_json(self) -> str:
        """Converts match info to json"""
        return json.dumps(
            {"file": self.file, "meta": self.meta, "matches": self.matches}
        )


class Database:
    def __init__(self, redis_host: str, redis_port: int) -> None:
        self.redis: Any = StrictRedis(
            host=redis_host, port=redis_port, decode_responses=True
        )
        self.engine = create_engine(app_config.database.url)

    def __schedule(self, agent: str, task: Any, *args: Any) -> None:
        """Schedules the task to agent group `agent` using rq."""
        Queue(agent, connection=self.redis).enqueue(
            task, *args, job_timeout=app_config.rq.job_timeout
        )

    def get_job_ids(self) -> List[JobId]:
        """Gets IDs of all jobs in the database"""
        with Session(self.engine) as session:
            jobs = session.exec(select(Job)).all()
            return [j.id for j in jobs]

    def cancel_job(self, job: JobId, error=None) -> None:
        """Sets the job status to cancelled, with optional error message"""
        with Session(self.engine) as session:
            session.execute(
                update(Job)
                .where(Job.id == job)
                .values(status="cancelled", finished=int(time()))
            )
            session.commit()

    def fail_job(self, job: JobId, message: str) -> None:
        """Sets the job status to cancelled with provided error message."""
        self.cancel_job(job, message)

    def get_job(self, job: JobId) -> Job:
        """Retrieves a job from the database. Tries to fix corrupted objects"""
        with Session(self.engine) as session:
            return session.exec(select(Job).where(Job.id == job)).one()

    def remove_query(self, job: JobId) -> None:
        """Sets the job status to removed"""
        with Session(self.engine) as session:
            session.execute(
                update(Job).where(Job.id == job).values(status="removed")
            )
            session.commit()

    def add_match(self, job: JobId, match: MatchInfo) -> None:
        self.redis.rpush(f"meta:{job}", match.to_json())

    def job_contains(self, job: JobId, ordinal: int, file_path: str) -> bool:
        """Make sure that the file path is in the job results"""
        file_list = self.redis.lrange(f"meta:{job}", ordinal, ordinal)
        return file_list and file_path == json.loads(file_list[0])["file"]

    def job_start_work(self, job: JobId, in_progress: int) -> None:
        """Updates the number of files being processed right now.
        :param job: ID of the job being updated.
        :param in_progress: Number of files in the current work unit.
        """
        with Session(self.engine) as session:
            session.execute(
                update(Job)
                .where(Job.id == job)
                .values(files_in_progress=Job.files_in_progress + in_progress)
            )
            session.commit()

    def agent_finish_job(self, job: JobId) -> None:
        """Decrements the number of active agents in the given job. If there
        are no more agents, job status is changed to done."""
        with Session(self.engine) as session:
            (agents_left,) = session.execute(
                update(Job)
                .where(Job.id == job)
                .values(agents_left=Job.agents_left - 1)
                .returning(Job.agents_left)
            ).one()
            if agents_left == 0:
                session.execute(
                    update(Job)
                    .where(Job.id == job)
                    .values(finished=int(time()), status="done")
                )
            session.commit()

    def agent_add_tasks_in_progress(
        self, job: JobId, agent: str, tasks: int
    ) -> None:
        """Increments (or decrements, for negative tasks) the number of tasks
        that are in progress for agent. This number should always be positive
        for jobs in status inprogress. This function will automatically call
        agent_finish_job if the agent has no more tasks left"""
        new_tasks = self.redis.incrby(f"agentjob:{agent}:{job}", tasks)
        assert new_tasks >= 0
        if new_tasks == 0:
            self.agent_finish_job(job)

    def job_update_work(
        self, job: JobId, processed: int, matched: int, errored: int
    ) -> int:
        """Updates progress for the job. This will increment numbers processed,
        inprogress, errored and matched files.
        Returns the number of processed files after the operation."""
        with Session(self.engine) as session:
            (files_processed,) = session.execute(
                update(Job)
                .where(Job.id == job)
                .values(
                    files_processed=Job.files_processed + processed,
                    files_in_progress=Job.files_in_progress - processed,
                    files_matched=Job.files_matched + matched,
                    files_errored=Job.files_errored + errored,
                )
                .returning(Job.files_processed)
            ).one()
            session.commit()
            return files_processed

    def init_job_datasets(self, job: JobId, num_datasets: int) -> None:
        """Sets total_datasets and datasets_left, and status to processing"""
        with Session(self.engine) as session:
            session.execute(
                update(Job)
                .where(Job.id == job)
                .values(
                    total_datasets=num_datasets,
                    datasets_left=num_datasets,
                    status="processing",
                )
            )
            session.commit()

    def dataset_query_done(self, job: JobId):
        """Decrements the number of datasets left by one."""
        with Session(self.engine) as session:
            session.execute(
                update(Job)
                .where(Job.id == job)
                .values(datasets_left=Job.datasets_left - 1)
            )
            session.commit()

    def create_search_task(
        self,
        rule_name: str,
        rule_author: str,
        raw_yara: str,
        files_limit: int,
        reference: str,
        taints: List[str],
        agents: List[str],
    ) -> JobId:
        """Creates a new job object in the db, and schedules daemon tasks."""
        job = "".join(
            random.choice(string.ascii_uppercase + string.digits)
            for _ in range(12)
        )
        with Session(self.engine) as session:
            obj = Job(
                id=job,
                status="new",
                rule_name=rule_name,
                rule_author=rule_author,
                raw_yara=raw_yara,
                submitted=int(time()),
                files_limit=files_limit,
                reference=reference,
                files_in_progress=0,
                files_processed=0,
                files_matched=0,
                files_errored=0,
                total_files=0,
                agents_left=len(agents),
                datasets_left=0,
                total_datasets=0,
                taints=taints,
            )
            session.add(obj)
            session.commit()

        from . import tasks

        for agent in agents:
            self.__schedule(agent, tasks.start_search, job)
        return job

    def get_job_matches(
        self, job: JobId, offset: int = 0, limit: Optional[int] = None
    ) -> MatchesSchema:
        if limit is None:
            end = -1
        else:
            end = offset + limit - 1
        meta = self.redis.lrange(f"meta:{job}", offset, end)
        matches = [json.loads(m) for m in meta]
        for match in matches:
            # Compatibility fix for old jobs, without sha256 metadata key.
            if "sha256" not in match["meta"]:
                match["meta"]["sha256"] = {
                    "display_text": "0" * 64,
                    "hidden": True,
                }
        return MatchesSchema(job=self.get_job(job), matches=matches)

    def update_job_files(self, job: JobId, total_files: int) -> int:
        """Add total_files to the specified job, and return a new total."""
        with Session(self.engine) as session:
            (total_files,) = session.execute(
                update(Job)
                .where(Job.id == job)
                .values(total_files=Job.total_files + total_files)
                .returning(Job.total_files)
            ).one()
            session.commit()
        return total_files

    def register_active_agent(
        self,
        group_id: str,
        ursadb_url: str,
        plugins_spec: Dict[str, Dict[str, str]],
        active_plugins: List[str],
    ) -> None:
        self.redis.hset(
            "agents",
            group_id,
            AgentSpecSchema(
                ursadb_url=ursadb_url,
                plugins_spec=plugins_spec,
                active_plugins=active_plugins,
            ).json(),
        )

    def get_active_agents(self) -> Dict[str, AgentSpecSchema]:
        return {
            name: AgentSpecSchema.parse_raw(spec)
            for name, spec in self.redis.hgetall("agents").items()
        }

    def get_core_config(self) -> Dict[str, str]:
        """Gets a list of configuration fields for the mquery core."""
        return {
            # Autentication-related config
            "auth_enabled": "Enable and force authentication for all users ('true' or 'false')",
            "auth_default_roles": "Comma separated list of roles available to everyone (available roles: admin, user)",
            # OpenID Authentication config
            "openid_url": "OpenID Connect base url",
            "openid_client_id": "OpenID client ID",
            "openid_secret": "Secret used for JWT token verification",
            # Query and performance config
            "query_allow_slow": "Allow users to run queries that will end up scanning the whole malware collection",
        }

    def get_config(self) -> List[ConfigSchema]:
        # { plugin_name: { field: description } }
        config_fields: Dict[str, Dict[str, str]] = defaultdict(dict)
        config_fields[MQUERY_PLUGIN_NAME] = self.get_core_config()
        # Merge all config fields
        for agent_spec in self.get_active_agents().values():
            for plugin, fields in agent_spec.plugins_spec.items():
                config_fields[plugin].update(fields)
        # Transform fields into ConfigSchema
        # { plugin_name: { field: ConfigSchema } }
        plugin_configs = {
            plugin: {
                key: ConfigSchema(
                    plugin=plugin, key=key, value="", description=description
                )
                for key, description in spec.items()
            }
            for plugin, spec in config_fields.items()
        }
        # Get configuration values for each plugin
        for plugin, spec in plugin_configs.items():
            config = self.get_plugin_config(plugin)
            for key, value in config.items():
                if key in plugin_configs[plugin]:
                    plugin_configs[plugin][key].value = value
        # Flatten to the target form
        return [
            plugin_configs[plugin][key]
            for plugin in sorted(plugin_configs.keys())
            for key in sorted(plugin_configs[plugin].keys())
        ]

    def get_plugin_config(self, plugin_name: str) -> Dict[str, str]:
        with Session(self.engine) as session:
            entries = session.exec(
                select(ConfigEntry).where(ConfigEntry.plugin == plugin_name)
            ).all()
            return {e.key: e.value for e in entries}

    def get_mquery_config_key(self, key: str) -> Optional[str]:
        with Session(self.engine) as session:
            statement = select(ConfigEntry).where(
                and_(
                    ConfigEntry.plugin == MQUERY_PLUGIN_NAME,
                    ConfigEntry.key == key,
                )
            )
            entry = session.exec(statement).one_or_none()
            return entry.value if entry else None

    def set_config_key(self, plugin_name: str, key: str, value: str) -> None:
        with Session(self.engine) as session:
            entry = session.exec(
                select(ConfigEntry).where(
                    ConfigEntry.plugin == plugin_name,
                    ConfigEntry.key == key,
                )
            ).one_or_none()
            if not entry:
                entry = ConfigEntry(plugin=plugin_name, key=key)
            entry.value = value
            session.add(entry)

    def cache_get(self, key: str, expire: int) -> Optional[str]:
        value = self.redis.get(f"cached:{key}")
        if value is not None:
            self.redis.expire(f"cached:{key}", expire)
        return value

    def cache_store(self, key: str, value: str, expire: int) -> None:
        self.redis.setex(f"cached:{key}", expire, value)


def init_db() -> None:
    engine = create_engine(app_config.database.url, echo=True)
    SQLModel.metadata.create_all(engine)


if __name__ == "__main__":
    init_db()
