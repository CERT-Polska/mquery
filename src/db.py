from typing import List, Optional, Dict, Any
from schema import JobSchema, MatchesSchema, AgentSpecSchema, ConfigSchema
from time import time
import json
import random
import string
from redis import StrictRedis


class AgentTask:
    def __init__(self, type: str, data: str):
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
        self.redis.hmset(job.key, {"status": "cancelled"})

    def fail_job(self, job: JobId, message: str) -> None:
        """ Sets the job status to failed. """
        self.redis.hmset(job.key, {"status": "failed", "error": message})

    def get_job(self, job: JobId) -> JobSchema:
        data = self.redis.hgetall(job.key)
        return JobSchema(
            id=job.hash,
            status=data.get("status", "ERROR"),
            rule_name=data.get("rule_name", "ERROR"),
            rule_author=data.get("rule_author", None),
            raw_yara=data.get("raw_yara", "ERROR"),
            submitted=data.get("submitted", 0),
            priority=data.get("priority", "medium"),
            files_processed=int(data.get("files_processed", 0)),
            files_matched=int(data.get("files_matched", 0)),
            files_in_progress=int(data.get("files_in_progress", 0)),
            total_files=int(data.get("total_files", 0)),
            iterator=data.get("iterator", None),
            taint=data.get("taint", None),
        )

    def add_match(self, job: JobId, match: MatchInfo) -> None:
        self.redis.rpush(job.meta_key, match.to_json())

    def job_contains(self, job: JobId, ordinal: str, file_path: str) -> bool:
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
        self, job: JobId, files_processed: int, files_matched: int,
    ) -> None:
        """ Update progress for the job. This will increment number of files processed
        and matched, and if as a result all files are processed, will change the job
        status to `done`
        """
        self.redis.hincrby(job.key, "files_processed", files_processed)
        self.redis.hincrby(job.key, "files_matched", files_matched)
        self.redis.hincrby(job.key, "files_in_progress", -files_processed)

    def create_search_task(
        self,
        rule_name: str,
        rule_author: str,
        raw_yara: str,
        priority: Optional[str],
        taint: Optional[str],
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
            "status": "processing",
            "rule_name": rule_name,
            "rule_author": rule_author,
            "raw_yara": raw_yara,
            "submitted": int(time()),
            "priority": priority,
            "files_in_progress": 0,
            "files_processed": 0,
            "files_matched": 0,
            "total_files": 0,
            "agents_left": len(agents),
        }
        if taint is not None:
            job_obj["taint"] = taint

        self.redis.hmset(job.key, job_obj)
        for agent in agents:
            self.redis.rpush(f"agent:{agent}:queue-search", job.hash)
        return job

    def create_reload_task(self, agents: List[str]):
        for agent in agents:
            self.redis.rpush(f"agent:{agent}:queue-reload", "all")

    def get_job_matches(
        self, job: JobId, offset: int, limit: int
    ) -> MatchesSchema:
        meta = self.redis.lrange(
            "meta:" + job.hash, offset, offset + limit - 1
        )
        return MatchesSchema(
            job=self.get_job(job), matches=[json.loads(m) for m in meta]
        )

    def agent_get_task(self, agent_id: str) -> AgentTask:
        agent_prefix = f"agent:{agent_id}"
        task_queues = [
            f"{agent_prefix}:queue-reload",
            f"{agent_prefix}:queue-search",
            f"{agent_prefix}:queue-yara",
        ]
        queue_task: Any = self.redis.blpop(task_queues)
        queue, task = queue_task

        if queue.endswith(":queue-search"):
            return AgentTask("search", task)

        if queue.endswith(":queue-yara"):
            return AgentTask("yara", task)

        if queue.endswith(":queue-reload"):
            return AgentTask("reload", task)

        raise RuntimeError("Unexpected queue")

    def update_job_files(self, job: JobId, total_files: int) -> None:
        self.redis.hincrby(job.key, "total_files", total_files)

    def agent_start_job(
        self, agent_id: str, job: JobId, iterator: str
    ) -> None:
        job_data = json.dumps({"job": job.key, "iterator": iterator})
        self.redis.rpush(f"agent:{agent_id}:queue-yara", job_data)

    def agent_finish_job(self, job: JobId) -> None:
        new_agents = self.redis.hincrby(job.key, "agents_left", -1)
        if new_agents <= 0:
            self.redis.hmset(job.key, {"status": "done"})

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

    def get_plugins_config(self) -> List[ConfigSchema]:
        config_fields: Dict[str, Dict[str, str]] = {}
        # Merge all config fields
        for agent_spec in self.get_active_agents().values():
            for name, fields in agent_spec.plugins_spec.items():
                if name not in config_fields:
                    config_fields[name] = {}
                config_fields[name].update(fields)
        # Transform fields into ConfigSchema
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
            config = self.get_plugin_configuration(plugin)
            for key, value in config.items():
                if key in plugin_configs[plugin]:
                    plugin_configs[plugin][key].value = value
        # Flatten to the target form
        return [
            plugin_configs[plugin][key]
            for plugin in sorted(plugin_configs.keys())
            for key in sorted(plugin_configs[plugin].keys())
        ]

    def get_plugin_configuration(self, plugin_name: str) -> Dict[str, str]:
        return self.redis.hgetall(f"plugin:{plugin_name}")

    def set_plugin_configuration_key(
        self, plugin_name: str, key: str, value: str
    ):
        self.redis.hset(f"plugin:{plugin_name}", key, value)

    def cache_get(self, key: str, expire: int) -> Optional[str]:
        value = self.redis.get(f"cached:{key}")
        if value is not None:
            self.redis.expire(f"cached:{key}", expire)
        return value

    def cache_store(self, key: str, value: str, expire: int):
        self.redis.setex(f"cached:{key}", expire, value)
