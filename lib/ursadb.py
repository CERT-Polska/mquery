import time
import json

import zmq


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
        socket.send(query)

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
        socket.send('index "{}" with [gram3, text4, hash4, wide8];'.format(path))
        response = socket.recv_string()
        socket.close()

    def status(self):
        socket = self.make_socket()
        socket.send('status;')
        response = socket.recv_string()
        socket.close()

        return json.loads(response)

    def close(self):
        pass
