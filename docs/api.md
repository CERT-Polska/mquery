# API

Launch mquery and browse to `/docs`.

![](./swagger.png?raw=true)

Mquery has a stable API that you can use to automate your work. It also
has internal API endpoints, that are used by the website - you can use them,
but may be changed in the future without warning.

Finally, many problems can be solved using the underlying ursadb's API.
Just remember that you shouldn't allow unauthenticated access to it, because
malicious user could index and query arbitrary files on the server's drive using
the API.

See [ursadb's documentation](https://cert-polska.github.io/ursadb/docs/api.html)
to learn more.

## Example

The [download](https://github.com/CERT-Polska/mquery/utils/download.py) script
is a good starting point for your own scripts. It uses only stable endpoints.
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
        "priority": "normal",
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
