import json
import time
import zmq  # type: ignore
from typing import Dict, Any


Json = Dict[str, Any]


class UrsaDb(object):
    def __init__(self, backend):
        self.backend = backend

    def make_socket(self, recv_timeout=2000):
        context = zmq.Context()
        socket = context.socket(zmq.REQ)
        socket.setsockopt(zmq.LINGER, 0)
        socket.setsockopt(zmq.RCVTIMEO, recv_timeout)
        socket.connect(self.backend)
        return socket

    def query(self, query, taint):
        socket = self.make_socket(recv_timeout=-1)

        start = time.clock()
        if taint:
            taint = taint.replace('"', '"')
            query = 'select with taints ["{}"] {};'.format(taint, query)
        else:
            query = "select {};".format(query)
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

        files = res.get("result", {}).get("files", [])

        return {"time": (end - start) * 1000, "files": files}

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

    def close(self):
        pass
