import json
import time
import zmq  # type: ignore
from typing import Dict, Any, List


Json = Dict[str, Any]


class PopResult:
    def __init__(self, was_locked: bool, files: List[str]) -> None:
        self.was_locked = was_locked
        self.files = files

    @property
    def should_drop_iterator(self) -> bool:
        """ Is it safe to remove the iterator after this operation? """
        if self.was_locked:
            return False
        return len(self.files) == 0


class UrsaDb:
    def __init__(self, backend: str) -> None:
        self.backend = backend

    def make_socket(self, recv_timeout: int = 2000) -> zmq.Context:
        context = zmq.Context()
        socket = context.socket(zmq.REQ)
        socket.setsockopt(zmq.LINGER, 0)
        socket.setsockopt(zmq.RCVTIMEO, recv_timeout)
        socket.connect(self.backend)
        return socket

    def query(self, query: str, taint: str) -> Json:
        socket = self.make_socket(recv_timeout=-1)

        start = time.clock()
        if taint:
            taint = taint.replace('"', '\\"')
            query = f'select with taints ["{taint}"] into iterator {query};'
        else:
            query = f"select into iterator {query};"
        socket.send_string(query)

        response = socket.recv_string()
        socket.close()
        end = time.clock()

        res = json.loads(response)

        if "error" in res:
            return {
                "error": "ursadb failed: "
                + res.get("error", {}).get("message", "(no message)")
            }

        iterator = res["result"]["iterator"]
        file_count = res["result"]["file_count"]

        return {
            "time": (end - start) * 1000,
            "iterator": iterator,
            "file_count": file_count,
        }

    def pop(self, iterator: str, count: int) -> PopResult:
        socket = self.make_socket(recv_timeout=-1)

        query = f'iterator "{iterator}" pop {count};'
        socket.send_string(query)

        response = socket.recv_string()
        socket.close()

        res = json.loads(response)
        if "error" in res:
            if res["error"].get("retry", False):
                # iterator locked, try again in a sec
                return PopResult(True, [])
            # return empty file set - this will clear the job from the db!
            return PopResult(False, [])

        return PopResult(False, res["result"]["files"])

    def status(self) -> Json:
        socket = self.make_socket()
        socket.send_string("status;")
        response = socket.recv_string()
        socket.close()

        return json.loads(response)

    def topology(self) -> Json:
        socket = self.make_socket()
        socket.send_string("topology;")
        response = socket.recv_string()
        socket.close()

        return json.loads(response)

    def execute_command(self, command: str) -> Json:
        socket = self.make_socket(recv_timeout=-1)
        socket.send_string(command)
        response = socket.recv_string()
        socket.close()

        return json.loads(response)

    def close(self) -> None:
        pass
