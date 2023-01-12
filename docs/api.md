# API

Launch mquery and browse to `/docs`.

![](./swagger.png?raw=true)

Mquery has a stable API that you can use to automate your work. It also
has internal API endpoints, that are used by the website - you can use them,
but they may change in the future without warning.

## Mquery API example

The [mquery](https://github.com/CERT-Polska/mquery/utils/mquery.py) script
is a good starting point for your scripts. It uses only stable endpoints.
The interesting part of the script is:

```python
#!/usr/bin/python3

import time
import requests

mquery_server = "http://localhost"  # hardcoded to localhost

yara_rule = """
rule test {
    strings: $a = "Exception"
    condition: $a
}
"""  # hardcoded yara rule

job_id = requests.post(
    f"{mquery_server}/api/query",
    json={
        "method": "query",
        "raw_yara": yara_rule,
        "taint": None,
        "method": "query",
    },
).json()["query_hash"]

offset = 0
while True:
    out = requests.get(
        f"{mquery_server}/api/matches/{job_id}?offset={offset}&limit=50"
    ).json()

    for match in out["matches"]:
        file_path = match["file"]
        sha256 = match["meta"]["sha256"]["display_text"]
        print(sha256)
        with open(sha256, "wb") as outf:
            content = requests.get(
                f"{mquery_server}/api/download",
                {"job_id": job_id, "ordinal": offset, "file_path": file_path,},
            ).content
            outf.write(content)
        offset += 1

    if out["job"]["status"] in ["cancelled", "failed", "done", "removed"]:
        break

    time.sleep(1.0)
```

## Ursadb API example

Many things that are not exposed by mquery can be done using the underlying
Ursadb's API. Just remember that you shouldn't allow unauthenticated access to it,
because a malicious user can use the API to index and query arbitrary files on the
server's drive.

See [ursadb's syntax documentation](https://cert-polska.github.io/ursadb/docs/syntax.html)
to learn more.

[`compactall`](https://github.com/CERT-Polska/mquery/blob/master/src/utils/compactall.py)
is a very simple example of this type of integration:

```python
ursa = UrsaDb("tcp://localhost:9281")
last_datasets = None
while True:
    datasets = set(
        ursa.execute_command("topology;")["result"]["datasets"].keys()
    )
    logging.info("%s datasets left.", len(datasets))
    if datasets == last_datasets:
        # Nothing can be compacted anymore
        break

    start = time.time()
    ursa.execute_command(f"compact smart;")
    end = time.time()
    logging.info("Compacting took %s seconds...", (end - start))
    last_datasets = datasets
```

Where the `Ursadb` object is just a very thin wrapper around zeromq:

```python
def make_socket(self, recv_timeout: int = 2000) -> zmq.Context:
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.setsockopt(zmq.LINGER, 0)
    socket.setsockopt(zmq.RCVTIMEO, recv_timeout)
    socket.connect(self.backend)
    return socket

def execute_command(self, command: str) -> Json:
    socket = self.make_socket(recv_timeout=-1)
    socket.send_string(command)
    response = socket.recv_string()
    socket.close()
    return json.loads(response)
```
