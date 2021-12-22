from collections import defaultdict
from typing import List, Optional, Dict, Any
from schema import JobSchema, MatchesSchema, AgentSpecSchema, ConfigSchema
from time import time
import json
import random
import string
from redis import StrictRedis
from enum import Enum


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


class JobId:
    """ Represents a unique job ID in redis. Looks like this: `job:IU32AD3` """

    def __init__(self, key: str) -> None:
        """ Creates a new JobId object. Can take both key and raw hash. """
        if not key.startswith("job:"):
            key = f"job:{key}"
        self.key = key
        self.hash = key[4:]

    @property
    def meta_key(self) -> str:
        """ Every job has exactly one related meta key"""
        return f"meta:{self.hash}"

    def __repr__(self) -> str:
        return self.key


class MatchInfo:
    """ Represents information about a single match """

    def __init__(
        self, file: str, meta: Dict[str, Any], matches: List[str]
    ) -> None:
        self.file = file
        self.meta = meta
        self.matches = matches

    def to_json(self) -> str:
        """ Converts match info to json """
        return json.dumps(
            {"file": self.file, "meta": self.meta, "matches": self.matches}
        )


class Database:
    def __init__(self, redis_host: str, redis_port: int) -> None:
        self.redis = StrictRedis(
            host=redis_host, port=redis_port, decode_responses=True
        )

    def get_yara_by_job(self, job: JobId) -> str:
        """ Gets yara rule associated with job """
        return self.redis.hget(job.key, "raw_yara")

    def get_job_status(self, job: JobId) -> str:
        """ Gets status of the specified job """
        return self.redis.hget(job.key, "status")

    def get_job_ids(self) -> List[JobId]:
        """ Gets IDs of all jobs in the database """
        return [JobId(key) for key in self.redis.keys("job:*")]

    def cancel_job(self, job: JobId) -> None:
        """ Sets the job status to cancelled """
        self.redis.hmset(
            job.key, {"status": "cancelled", "finished": int(time())}
        )

    def fail_job(self, job: JobId, message: str) -> None:
        """ Sets the job status to failed. """
        self.redis.hmset(
            job.key,
            {"status": "failed", "error": message, "finished": int(time())},
        )

    def get_job(self, job: JobId) -> JobSchema:
        data = self.redis.hgetall(job.key)
        return JobSchema(
            id=job.hash,
            status=data.get("status", "ERROR"),
            error=data.get("error", None),
            rule_name=data.get("rule_name", "ERROR"),
            rule_author=data.get("rule_author", None),
            raw_yara=data.get("raw_yara", "ERROR"),
            submitted=data.get("submitted", 0),
            finished=data.get("finished", None),
            priority=data.get("priority", "medium"),
            files_limit=data.get("files_limit", 0),
            files_processed=int(data.get("files_processed", 0)),
            files_matched=int(data.get("files_matched", 0)),
            files_in_progress=int(data.get("files_in_progress", 0)),
            total_files=int(data.get("total_files", 0)),
            files_errored=int(data.get("files_errored", 0)),
            reference=data.get("reference", ""),
            iterator=data.get("iterator", None),
            taints=json.loads(data.get("taints", "[]")),
            total_datasets=data.get("total_datasets", 0),
            datasets_left=data.get("datasets_left", 0),
        )

    def remove_query(self, job: JobId) -> None:
        """ Sets the job status to removed """
        self.redis.hmset(job.key, {"status": "removed"})

    def add_match(self, job: JobId, match: MatchInfo) -> None:
        self.redis.rpush(job.meta_key, match.to_json())

    def job_contains(self, job: JobId, ordinal: int, file_path: str) -> bool:
        file_list = self.redis.lrange(job.meta_key, ordinal, ordinal)
        return file_list and file_path == json.loads(file_list[0])["file"]

    def job_start_work(self, job: JobId, files_in_progress: int) -> None:
        """ Updates the number of files being processed right now.
        :param job: ID of the job being updated.
        :type job: JobId
        :param files_in_progress: Number of files in the current work unit.
        :type files_in_progress: int
        """
        self.redis.hincrby(job.key, "files_in_progress", files_in_progress)

    def job_update_work(
        self, job: JobId, files_processed: int, files_matched: int
    ) -> None:
        """ Update progress for the job. This will increment number of files processed
        and matched, and if as a result all files are processed, will change the job
        status to `done`
        """
        self.redis.hincrby(job.key, "files_processed", files_processed)
        self.redis.hincrby(job.key, "files_in_progress", -files_processed)
        self.redis.hincrby(job.key, "files_matched", files_matched)

    def job_update_error(self, job: JobId, files_errored: int) -> None:
        """ Update error for the job if it appears during agents' work.
        This will increment number of files errored and write them to the variable.
        """
        self.redis.hincrby(job.key, "files_errored", files_errored)

    def create_search_task(
        self,
        rule_name: str,
        rule_author: str,
        raw_yara: str,
        priority: Optional[str],
        files_limit: int,
        reference: str,
        taints: List[str],
        agents: List[str],
    ) -> JobId:
        job = JobId(
            "".join(
                random.SystemRandom().choice(
                    string.ascii_uppercase + string.digits
                )
                for _ in range(12)
            )
        )
        job_obj = {
            "status": "new",
            "rule_name": rule_name,
            "rule_author": rule_author,
            "raw_yara": raw_yara,
            "submitted": int(time()),
            "priority": priority or "medium",
            "files_limit": files_limit,
            "reference": reference,
            "files_in_progress": 0,
            "files_processed": 0,
            "files_matched": 0,
            "total_files": 0,
            "files_errored": 0,
            "agents_left": len(agents),
            "datasets_left": 0,
            "total_datasets": 0,
        }

        job_obj["taints"] = json.dumps(taints)

        self.redis.hmset(job.key, job_obj)
        for agent in agents:
            self.redis.rpush(f"agent:{agent}:queue-search", job.hash)
        return job

    def broadcast_command(self, command: str) -> None:
        for agent in self.get_active_agents().keys():
            self.redis.rpush(f"agent:{agent}:queue-command", command)

    def init_job_datasets(
        self, agent_id: str, job: JobId, datasets: List[str]
    ) -> None:
        if datasets:
            self.redis.lpush(f"job-ds:{agent_id}:{job.hash}", *datasets)
            self.redis.hincrby(job.key, "total_datasets", len(datasets))
            self.redis.hincrby(job.key, "datasets_left", len(datasets))
        self.redis.hset(job.key, "status", "processing")

    def get_next_search_dataset(
        self, agent_id: str, job: JobId
    ) -> Optional[str]:
        return self.redis.lpop(f"job-ds:{agent_id}:{job.hash}")

    def dataset_query_done(self, job: JobId):
        self.redis.hincrby(job.key, "datasets_left", -1)

    def job_datasets_left(self, agent_id: str, job: JobId) -> int:
        return self.redis.llen(f"job-ds:{agent_id}:{job.hash}")

    def agent_continue_search(self, agent_id: str, job: JobId) -> None:
        self.redis.rpush(f"agent:{agent_id}:queue-search", job.hash)

    def get_job_matches(
        self, job: JobId, offset: int = 0, limit: Optional[int] = None
    ) -> MatchesSchema:
        if limit is None:
            end = -1
        else:
            end = offset + limit - 1
        meta = self.redis.lrange("meta:" + job.hash, offset, end)
        matches = [json.loads(m) for m in meta]
        for match in matches:
            # Compatibility fix for old jobs, without sha256 metadata key.
            if "sha256" not in match["meta"]:
                match["meta"]["sha256"] = {
                    "display_text": "0" * 64,
                    "hidden": True,
                }
        return MatchesSchema(job=self.get_job(job), matches=matches)

    def reload_configuration(self, config_version: int):
        # Send request to any of agents that configuration must be reloaded
        self.redis.lpush(f"config-reload:{config_version}", "reload")
        # After 300 seconds of inactivity: reload request is deleted
        self.redis.expire(f"config-reload:{config_version}", 300)

    def agent_get_task(self, agent_id: str, config_version: int) -> AgentTask:
        agent_prefix = f"agent:{agent_id}"
        # config-reload is a notification queue that is set by web to notify
        # agents that configuration has been changed
        task_queues = [
            f"config-reload:{config_version}",
            f"{agent_prefix}:queue-command",
            f"{agent_prefix}:queue-search",
            f"{agent_prefix}:queue-yara",
        ]
        queue_task: Any = self.redis.blpop(task_queues)
        queue, task = queue_task

        if queue == f"config-reload:{config_version}":
            return AgentTask(TaskType.RELOAD, task)

        if queue.endswith(":queue-command"):
            return AgentTask(TaskType.COMMAND, task)

        if queue.endswith(":queue-search"):
            return AgentTask(TaskType.SEARCH, task)

        if queue.endswith(":queue-yara"):
            return AgentTask(TaskType.YARA, task)

        raise RuntimeError("Unexpected queue")

    def update_job_files(self, job: JobId, total_files: int) -> int:
        return self.redis.hincrby(job.key, "total_files", total_files)

    def agent_start_job(
        self, agent_id: str, job: JobId, iterator: str
    ) -> None:
        job_data = json.dumps({"job": job.key, "iterator": iterator})
        self.redis.rpush(f"agent:{agent_id}:queue-yara", job_data)

    def agent_finish_job(self, job: JobId) -> None:
        new_agents = self.redis.hincrby(job.key, "agents_left", -1)
        if new_agents <= 0:
            self.redis.hmset(
                job.key, {"status": "done", "finished": int(time())}
            )

    def has_pending_search_tasks(self, agent_id: str, job: JobId) -> bool:
        return self.redis.llen(f"job-ds:{agent_id}:{job.hash}") == 0

    def register_active_agent(
        self,
        agent_id: str,
        ursadb_url: str,
        plugins_spec: Dict[str, Dict[str, str]],
        active_plugins: List[str],
    ) -> None:
        self.redis.hset(
            "agents",
            agent_id,
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
            "auth_enabled": "Enable and force authentication for all users",
            "auth_default_roles": "Comma separated list of roles available to everyone",
            # OpenID Authentication config
            "openid_auth_url": "OpenID Connect auth url",
            "openid_login_url": "OpenID Connect login url",
            "openid_client_id": "OpenID client ID",
            "openid_secret": "Secret used for JWT token verification",
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

    def get_config_version(self) -> int:
        return int(self.redis.get("plugin-version") or 0)

    def get_plugin_config(self, plugin_name: str) -> Dict[str, str]:
        return self.redis.hgetall(f"plugin:{plugin_name}")

    def get_config_key(self, plugin_name: str, key: str) -> Optional[str]:
        return self.redis.hget(f"plugin:{plugin_name}", key)

    def get_mquery_config_key(self, key: str) -> Optional[str]:
        return self.redis.hget(f"plugin:{MQUERY_PLUGIN_NAME}", key)

    def set_config_key(self, plugin_name: str, key: str, value: str) -> None:
        self.redis.hset(f"plugin:{plugin_name}", key, value)
        prev_version = self.redis.incrby("plugin-version", 1) - 1
        self.reload_configuration(prev_version)

    def cache_get(self, key: str, expire: int) -> Optional[str]:
        value = self.redis.get(f"cached:{key}")
        if value is not None:
            self.redis.expire(f"cached:{key}", expire)
        return value

    def cache_store(self, key: str, value: str, expire: int) -> None:
        self.redis.setex(f"cached:{key}", expire, value)
