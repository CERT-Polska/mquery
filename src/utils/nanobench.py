"""
The "official" benchmark suite for ursadb. Right now it's used by developers,
to asses the database performance and evaluate improvements/regressions.

It's not representative of anything by any means - for example, effects of
disk cache are ignored. It's just a good sniff test for the overall
performance of the system.
"""

import json
import zmq
import logging
import argparse
from datetime import datetime


def benchmark(socket, query):
    total_ms = 0
    TRY_COUNT = 1
    expected_resp = None
    for i in range(TRY_COUNT):
        start = datetime.now()
        socket.send_string(query)
        raw_resp = socket.recv()
        end = datetime.now()
        if expected_resp is None:
            expected_resp = raw_resp
        assert raw_resp == expected_resp
        total_ms += (end - start).total_seconds() * 1000
        print
    if expected_resp is None or "error" in json.loads(expected_resp):
        fileno = "[ERRORED]"
    else:
        fileno = len(json.loads(expected_resp)["result"]["files"])
    print(f"{query:<60} average {total_ms/TRY_COUNT: 10.3f} files: {fileno}")


def nano(socket):
    """ Simple queries. They should work on any database """
    benchmark(socket, 'select "abc";')
    benchmark(socket, 'select "abcdefgh";')
    benchmark(socket, 'select "abc" & "qwe" & "zxc";')
    benchmark(socket, 'select "abc" | "qwe" | "zxc";')
    benchmark(socket, 'select min 1 of ("abc", "qwe", "zxc");')
    benchmark(socket, 'select min 2 of ("abc", "qwe", "zxc");')
    benchmark(socket, 'select min 3 of ("abc", "qwe", "zxc");')
    benchmark(socket, "select {61 62 6?};")
    benchmark(socket, "select {61 62 6? 63};")
    benchmark(socket, "select {61 62 6? 63 64};")


def mini(socket):
    """ Reasonable queries. They may take some time, but should return results
    in a reasonable time. """
    benchmark(socket, "select {60 61 62 ??};")
    benchmark(socket, "select {60 61 62 ?? 63};")
    benchmark(socket, "select {60 61 62 ?? 63 64};")
    benchmark(socket, "select {61 62 ??};")
    benchmark(socket, "select {61 62 ?? 63};")
    benchmark(socket, "select {61 62 ?? 63 64};")
    benchmark(socket, "select {(61|62) (62|63) (64|65)};")
    benchmark(socket, "select {(61|62) (62|63) (64|65) (66|67)};")
    benchmark(socket, "select {(61|62) (62|63) (64|65) (66|67) (68|69)};")


def heavyduty(socket):
    """ Heavy queries. Used to benchmark querygraphs. Most of them will take
    forever on a large real-world database. """
    benchmark(socket, "select {?1 ?2 ?3};")
    benchmark(socket, "select {?1 ?2 ?3 ?4};")
    benchmark(socket, "select {?1 ?2 ?3 ?4 ?5};")
    benchmark(socket, "select {?1 ?2 ?3 ?4 ?5 ?6};")
    benchmark(socket, "select {?1 ?2 ?3 ?4 ?5 ?6 ?7};")
    benchmark(socket, "select {?1 ?2 ?3 ?? ?5 ?6 ?7};")
    benchmark(socket, "select {62 ?? 63 ?? 64};")
    benchmark(socket, "select {1? 2? ?? 1? 2?};")
    benchmark(socket, "select {61 62 ?? 63 ?? 64 65};")
    benchmark(socket, "select {61 62 ?? 63 ?? 64 ?? 65 66};")
    benchmark(socket, "select {61 62 63 64 64 1? 2? 3? 4? 5?};")
    benchmark(socket, "select {1? 2? 3? 4? 5? 61 62 63 64 64};")
    benchmark(socket, "select {61 62 63 64 ?? ??};")
    benchmark(socket, "select {?? ?? 61 62 63 64};")
    benchmark(socket, "select {61 62 63 64 ?? ?? 65};")
    benchmark(socket, "select {65 ?? ?? 61 62 63 64};")
    benchmark(socket, "select {?1 ?2 ?3 ?4 ?5 ?6};")
    benchmark(socket, "select {61 62 63} & {?1 ?2 ?3 ?4 ?5 ?6};")
    benchmark(socket, "select {61 62 63 ?? ?? ?? ?1 ?2 ?3 ?4 ?5 ?6 ?8};")
    benchmark(socket, "select {?1 ?2 ?3 ?4 ?5 ?6} & {61 62 63};")
    benchmark(socket, "select {?1 ?2 ?3 ?4 ?5 ?6 ?? ?? ?? 61 62 63};")


def main() -> None:
    logging.basicConfig(level=logging.INFO)

    LEVELS = {
        "nano": 0,
        "mini": 1,
        "heavyduty": 2,
    }

    parser = argparse.ArgumentParser(description="Simple benchmark utility.")
    parser.add_argument(
        "--ursadb",
        help="URL of the ursadb instance.",
        default="tcp://localhost:9281",
    )
    parser.add_argument(
        "--level",
        help="How hard should the tests be.",
        choices=LEVELS.keys(),
        default="heavyduty",
    )

    args = parser.parse_args()
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.setsockopt(zmq.LINGER, 0)
    socket.connect(args.ursadb)

    level = LEVELS[args.level]
    if level >= 0:
        nano(socket)
    if level >= 1:
        mini(socket)
    if level >= 2:
        heavyduty(socket)


main()
