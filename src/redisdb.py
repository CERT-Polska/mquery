from typing import Any, TYPE_CHECKING
from redis import StrictRedis
from rq import Queue  # type: ignore

from .config import app_config


if TYPE_CHECKING:
    from .db import JobId


class RedisDB:
    def __init__(self, redis_host: str, redis_port: int) -> None:
        self.redis: Any = StrictRedis(
            host=redis_host, port=redis_port, decode_responses=True
        )

    def start_search(self, agent: str, job: str) -> None:
        """Schedules the search task to agent group `agent` using rq."""
        from . import tasks
        Queue(agent, connection=self.redis).enqueue(
            tasks.start_search, job, job_timeout=app_config.rq.job_timeout
        )

    def add_tasks_in_progress(
        self, job: "JobId", agent: str, tasks: int
    ) -> bool:
        """Increments (or decrements, for negative `tasks`) the number of tasks
        that are in progress for agent. This value should always be positive
        for jobs in status inprogress. This function will return True if the
        agent has no more tasks left.
        """
        new_tasks = self.redis.incrby(f"agentjob:{agent}:{job}", tasks)
        assert new_tasks >= 0
        return new_tasks == 0
