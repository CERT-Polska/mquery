"""
Unit-tests for the ursadb library
"""

import sys
import pytest  # type: ignore
import json
import zmq  # type: ignore
import threading
from typing import Dict, Any

sys.path = [".."] + sys.path
from lib.ursadb import UrsaDb  # noqa


class UrsadbTestContext:
    def __init__(self, socket: zmq.Socket, ursadb: UrsaDb):
        self.socket = socket
        self.ursadb = ursadb

    def expect(self, request: str, response: Dict[str, Any]):
        def server_side():
            assert self.socket.recv_string() == request
            self.socket.send_string(json.dumps(response))

        threading.Thread(target=server_side).start()


@pytest.fixture(scope="session", autouse=True)
def db_context(request):
    IPC = "ipc:///tmp/ursadb-test"
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind(IPC)
    return UrsadbTestContext(socket, UrsaDb(IPC))


def test_successful_iterator_pop(db_context: UrsadbTestContext):
    db_context.expect(
        'iterator "iter_id" pop 3;',
        {"result": {"files": ["hmm", "xyz", "www"]}},
    )

    result = db_context.ursadb.pop("iter_id", 3)
    assert not result.should_drop_iterator
    assert result.files == ["hmm", "xyz", "www"]
    assert not result.was_locked


def test_incomplete_iterator_pop(db_context: UrsadbTestContext):
    db_context.expect(
        'iterator "iter_id" pop 3;', {"result": {"files": ["hmm"]}}
    )

    result = db_context.ursadb.pop("iter_id", 3)
    assert not result.should_drop_iterator
    assert result.files == ["hmm"]
    assert not result.was_locked


def test_iterator_pop_error(db_context: UrsadbTestContext):
    db_context.expect(
        'iterator "iter_id" pop 3;',
        {"error": {"message": "something didn't work"}},
    )

    result = db_context.ursadb.pop("iter_id", 3)
    assert result.should_drop_iterator
    assert result.files == []
    assert not result.was_locked


def test_locked_iterator(db_context: UrsadbTestContext):
    db_context.expect(
        'iterator "iter_id" pop 3;',
        {"error": {"message": "something didn't work", "retry": True}},
    )

    result = db_context.ursadb.pop("iter_id", 3)
    assert not result.should_drop_iterator
    assert result.files == []
    assert result.was_locked
