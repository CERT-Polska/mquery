import json
import time
import zmq  # type: ignore
from typing import Dict, Any, List, Optional


Json = Dict[str, Any]


class PopResult:
    def __init__(
        self,
        was_locked: bool,
        files: List[str],
        iterator_pos: int,
        total_files: int,
    ) -> None:
        self.was_locked = was_locked
        self.files = files
        self.iterator_pos = iterator_pos
        self.total_files = total_files

    @property
    def iterator_empty(self) -> bool:
        """Is it safe to remove the iterator after this operation?"""
        if self.was_locked:
            return False
        return self.iterator_pos >= self.total_files

    def __str__(self) -> str:
        """Pretty-print iterator showing all important information."""
        tag = "[locked] " if self.was_locked else ""
        pos = f"{self.iterator_pos}/{self.total_files}"
        return f"iterator {tag}with {len(self.files)} files ({pos})"


class UrsaDb:
    def __init__(self, backend: str) -> None:
        self.backend = backend

    def __execute(self, command: str, recv_timeout: int = 2000) -> Json:
        context = zmq.Context()
        try:
            socket = context.socket(zmq.REQ)
            socket.setsockopt(zmq.LINGER, 0)
            socket.setsockopt(zmq.RCVTIMEO, recv_timeout)
            socket.connect(self.backend)
            socket.send_string(command)
            return json.loads(socket.recv_string())
        finally:
            socket.close()

    def query(
        self,
        query: str,
        taints: List[str] | None = None,
        dataset: Optional[str] = None,
    ) -> Json:
        command = "select "
        if taints:
            taints_str = '", "'.join(taints)
            taints_whole_str = f'["{taints_str}"]'
            command += f"with taints {taints_whole_str} "
        if dataset:
            command += f'with datasets ["{dataset}"] '
        command += f"into iterator {query};"

        start = time.perf_counter()
        res = self.__execute(command, recv_timeout=-1)
        end = time.perf_counter()

        if "error" in res:
            error = res.get("error", {}).get("message", "(no message)")
            return {"error": f"ursadb failed: {error}"}

        return {
            "time": (end - start),
            "iterator": res["result"]["iterator"],
            "file_count": res["result"]["file_count"],
        }

    def pop(self, iterator: str, count: int) -> PopResult:
        res = self.__execute(f'iterator "{iterator}" pop {count};', -1)

        if "error" in res:
            if res["error"].get("retry", False):
                # iterator locked, try again in a sec
                return PopResult(True, [], 0, 0)
            # return empty file set - this will clear the job from the db!
            return PopResult(False, [], 0, 0)

        res = res["result"]
        iterator_pos = res["iterator_position"]
        total_files = res["total_files"]
        return PopResult(False, res["files"], iterator_pos, total_files)

    def status(self) -> Json:
        return self.__execute("status;")

    def topology(self) -> Json:
        return self.__execute("topology;")

    def execute_command(self, command: str) -> Json:
        return self.__execute(command, -1)
