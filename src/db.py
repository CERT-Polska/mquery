from typing import List, Tuple, Optional, Dict, Any
from schema import JobSchema, MatchesSchema, StorageSchema
from time import time
import json
import random
import string
import config
from datetime import datetime
from redis import StrictRedis


def make_redis() -> StrictRedis:
    return StrictRedis(
        host=config.REDIS_HOST, port=config.REDIS_PORT, decode_responses=True
    )


def get_list_name(priority: str) -> str:
    if priority == "low":
        return "list-yara-low"
    elif priority == "medium":
        return "list-yara-medium"
    else:
        return "list-yara-high"


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


class JobQueue:
    """ Represents one of the available job queues """

    def __init__(self, name: str) -> None:
        self.name = name

    @classmethod
    def available(cls) -> List["JobQueue"]:
        names = ["list-yara-high", "list-yara-medium", "list-yara-low"]
        return [cls(name) for name in names]

    def __repr__(self) -> str:
        return f"queue:{self.name}"


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
    def __init__(self) -> None:
        self.redis = make_redis()

    def get_yara_by_job(self, job: JobId) -> str:
        """ Gets yara rule associated with job """
        return self.redis.hget(job.key, "raw_yara")

    def get_job_submitted(self, job: JobId) -> int:
        """ Gets submission date of the job """
        return int(self.redis.hget(job.key, "submitted"))

    def get_job_status(self, job: JobId) -> str:
        """ Gets status of the specified job """
        return self.redis.hget(job.key, "status")

    def get_job_ids(self) -> List[JobId]:
        """ Gets IDs of all jobs in the database """
        return [JobId(key) for key in self.redis.keys("job:*")]

    def expire_job(self, job: JobId) -> None:
        """ Sets the job status to expired, and removes it from the db """
        self.redis.hset(job.key, "status", "expired")
        self.redis.delete(job.meta_key)

    def fail_job(
        self, queue: Optional[JobQueue], job: JobId, message: str
    ) -> None:
        """ Sets the job status to failed, and removes it from job queues """
        self.redis.hmset(job.key, {"status": "failed", "error": message})
        if queue:
            self.redis.lrem(queue.name, 0, job.hash)

    def cancel_job(self, job: JobId) -> None:
        """ Sets the job status to cancelled """
        self.redis.hmset(job.key, {"status": "cancelled"})

    def finish_job(self, queue: Optional[JobQueue], job: JobId) -> None:
        """ Sets the job status to done, and removes it from job queues """
        self.redis.hset(job.key, "status", "done")
        if queue:
            self.redis.lrem(queue.name, 0, job.hash)

    def set_job_to_processing(
        self, job: JobId, iterator: str, file_count: int
    ) -> None:
        self.redis.hmset(
            job.key,
            {
                "status": "processing",
                "iterator": iterator,
                "files_processed": 0,
                "files_matched": 0,
                "files_in_progress": 0,
                "total_files": file_count,
            },
        )

    def update_job(
        self, job: JobId, files_processed: int, files_matched: int
    ) -> None:
        self.redis.hincrby(job.key, "files_processed", files_processed)
        self.redis.hincrby(job.key, "files_matched", files_matched)

    def set_files_in_progress(
        self, job: JobId, files_in_progress: int
    ) -> None:
        self.redis.hincrby(job.key, "files_in_progress", files_in_progress)

    def update_files_in_progress(self, job: JobId) -> None:
        self.redis.hincrby(job.key, "files_in_progress", -1)

    def set_job_to_parsing(self, job: JobId) -> None:
        """ Sets the job status to parsing """
        self.redis.hmset(job.key, {"status": "parsing", "timestamp": time()})

    def set_job_to_querying(self, job: JobId) -> None:
        """ Sets the job status to querying """
        self.redis.hmset(job.key, {"status": "querying", "timestamp": time()})

    def gc_lock(self) -> bool:
        """ Tries to get a GC lock,and returns ture if succeeded """
        return bool(self.redis.set("gc-lock", "locked", ex=60, nx=True))

    def push_job_to_queue(self, job: JobSchema) -> None:
        list_name = get_list_name(job.priority)
        self.redis.lpush(list_name, job.id)

    def get_random_job_by_priority(self) -> Optional[Tuple[JobQueue, JobId]]:
        """ Tries to get a random job along with its queue """
        for queue in JobQueue.available():
            yara_jobs = self.redis.lrange(queue.name, 0, -1)
            if yara_jobs:
                return queue, JobId(random.choice(yara_jobs))
        return None

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

    def create_search_task(
        self,
        rule_name: str,
        rule_author: str,
        raw_yara: str,
        priority: Optional[str],
        taint: Optional[str],
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
            "priority": priority,
        }
        if taint is not None:
            job_obj["taint"] = taint

        self.redis.hmset(job.key, job_obj)
        self.redis.rpush("queue-search", job.hash)
        return job

    def get_job_matches(
        self, job: JobId, offset: int, limit: int
    ) -> MatchesSchema:
        p = self.redis.pipeline(transaction=False)
        p.hgetall(job.key)
        p.lrange("meta:" + job.hash, offset, offset + limit - 1)
        job, meta = p.execute()
        return MatchesSchema(job=job, matches=[json.loads(m) for m in meta])

    def run_command(self, command: str) -> None:
        self.redis.rpush("queue-commands", command)

    def get_task(self) -> Optional[Tuple[str, str]]:
        task_queues = ["queue-search", "queue-commands"]
        for queue in task_queues:
            task = self.redis.lpop(queue)
            if task is not None:
                return queue, task
        return None

    def unsafe_get_redis(self) -> StrictRedis:
        return self.redis

    def get_storage(self, storage_id: str) -> StorageSchema:
        data = self.redis.hgetall(storage_id)
        return StorageSchema(
            id=storage_id,
            name=data["name"],
            path=data["path"],
            indexing_job_id=None,
            last_update=datetime.fromtimestamp(data["timestamp"]),
            taints=data["taints"],
            enabled=data["enabled"],
        )

    def get_storages(self) -> List[StorageSchema]:
        return [
            self.get_storage(storage_id)
            for storage_id in self.redis.keys("storage:*")
        ]
