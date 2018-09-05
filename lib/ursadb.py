import time
import json
import zmq
import os,sys,inspect

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from config import INDEX_TYPE


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

    def query(self, query):
        socket = self.make_socket(recv_timeout=-1)

        start = time.clock()
        query = 'select {};'.format(query)
        socket.send_string(query)

        response = socket.recv_string()
        socket.close()
        end = time.clock()

        res = json.loads(response)

        if 'error' in res:
            return {
                'error': 'ursadb failed: ' + res.get('error', {}).get('message', '(no message)')
            }

        files = res.get('result', {}).get('files', [])

        return {
            'time': (end - start)*1000,
            'files': files
        }

    def index(self, path):
        socket = self.make_socket(recv_timeout=-1)
        socket.send_string('index "{path}" with [{index_type}];'.format(
            path=path, index_type=', '.join(INDEX_TYPE)))
        response = socket.recv_string()
        socket.close()

    def status(self):
        socket = self.make_socket()
        socket.send_string('status;')
        response = socket.recv_string()
        socket.close()

        return json.loads(response)

    def close(self):
        pass
