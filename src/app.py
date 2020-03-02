import json
import logging
import os
import random
import string
import time

from flask import (
    Flask,
    request,
    jsonify,
    send_file,
    send_from_directory,
    Response,
)
from werkzeug.exceptions import NotFound
from zmq import Again  # type: ignore

from lib.ursadb import UrsaDb
from lib.yaraparse import yara_traverse
from yaramod import Yaramod  # type: ignore

from util import make_redis, mquery_version
import config
from typing import Any

redis = make_redis()
app = Flask(__name__, static_folder="mqueryfront/build/static")
db = UrsaDb(config.BACKEND)


@app.after_request
def add_header(response: Response) -> Response:
    response.headers["X-Frame-Options"] = "deny"
    response.headers["Access-Control-Allow-Origin"] = request.host
    response.headers[
        "Access-Control-Allow-Headers"
    ] = "cache-control,x-requested-with,content-type,authorization"
    response.headers[
        "Access-Control-Allow-Methods"
    ] = "POST, PUT, GET, OPTIONS, DELETE"
    return response


@app.route("/api/download")
def download() -> Any:
    job_id = request.args["job_id"]
    file_path = request.args["file_path"]
    ordinal = request.args["ordinal"]

    file_list = redis.lrange("meta:" + job_id, ordinal, ordinal)

    if not file_list or file_path != json.loads(file_list[0])["file"]:
        raise NotFound("No such file in result set.")

    attach_name, ext = os.path.splitext(os.path.basename(file_path))
    ext = ext + "_"

    return send_file(
        file_path, as_attachment=True, attachment_filename=attach_name + ext
    )


@app.route("/api/query/<priority>", methods=["POST"])
def query(priority: str) -> Any:
    req = request.get_json()
    raw_yara = req["raw_yara"]

    try:
        rules = Yaramod().parse_string(raw_yara).rules
    except Exception as e:
        return jsonify({"error": f"Yara rule parsing failed{e}"}), 400

    if not rules:
        return jsonify({"error": "No rule was specified."}), 400

    if len(rules) > 1:
        return jsonify({"error": "More than one rule specified!"}), 400

    rule = rules[0]

    author_meta = rule.get_meta_with_name("author")
    if author_meta:
        rule_author = author_meta.value.pure_text
    else:
        rule_author = ""

    rule_name = rule.name

    try:
        rule_strings = {}
        for r_string in rule.strings:
            rule_strings[r_string.identifier] = r_string
        parsed = yara_traverse(rule.condition, rule_strings)

    except Exception as e:
        logging.exception("YaraParser failed")
        return jsonify({"error": f"Yara rule conversion failed: {e}"}), 400

    if req["method"] == "parse":
        return jsonify({"rule_name": rule_name, "parsed": parsed})

    job_hash = "".join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        for _ in range(12)
    )

    job_obj = {
        "status": "new",
        "max_files": -1,
        "rule_name": rule_name,
        "rule_author": rule_author,
        "parsed": parsed,
        "raw_yara": raw_yara,
        "submitted": int(time.time()),
        "priority": priority,
    }

    if req["method"] == "query_100":
        job_obj.update({"max_files": 100})

    redis.hmset("job:" + job_hash, job_obj)
    redis.rpush("queue-search", job_hash)

    return jsonify({"query_hash": job_hash})


@app.route("/api/matches/<hash>")
def matches(hash: str) -> Response:
    offset = int(request.args["offset"])
    limit = int(request.args["limit"])

    p = redis.pipeline(transaction=False)
    p.hgetall("job:" + hash)
    p.lrange("meta:" + hash, offset, offset + limit - 1)
    job, meta = p.execute()

    return jsonify({"job": job, "matches": [json.loads(m) for m in meta]})


@app.route("/api/job/<hash>")
def job_info(hash: str) -> Response:
    return jsonify(redis.hgetall("job:" + hash))


@app.route("/api/job/<job_id>", methods=["DELETE"])
def job_cancel(job_id: str) -> Response:
    redis.hmset("job:" + job_id, {"status": "cancelled"})

    return jsonify({"status": "ok"})


@app.route("/api/job")
def job_statuses() -> Response:
    jobs = redis.keys("job:*")
    jobs = sorted(
        [dict({"id": job[4:]}, **redis.hgetall(job)) for job in jobs],
        key=lambda o: o.get("submitted"),
        reverse=True,
    )

    return jsonify({"jobs": jobs})


@app.route("/api/backend")
def backend_status() -> Response:
    db_alive = True
    status = db.status()
    try:
        tasks = status.get("result", {}).get("tasks", [])
        ursadb_version = status.get("result", {}).get(
            "ursadb_version", "unknown"
        )
    except Again:
        db_alive = False
        tasks = []
        ursadb_version = []

    return jsonify(
        {
            "db_alive": db_alive,
            "tasks": tasks,
            "components": {
                "mquery": mquery_version(),
                "ursadb": str(ursadb_version),
            },
        }
    )


@app.route("/api/backend/datasets")
def backend_status_datasets() -> Response:
    db_alive = True

    try:
        datasets = db.topology().get("result", {}).get("datasets", [])
    except Again:
        db_alive = False
        datasets = []

    return jsonify({"db_alive": db_alive, "datasets": datasets})


@app.route("/query/<path:path>")
def serve_index(path: str) -> Any:
    return send_file("mqueryfront/build/index.html")


@app.route("/recent")
@app.route("/status")
@app.route("/query")
def serve_index_sub() -> Any:
    return send_file("mqueryfront/build/index.html")


@app.route("/", defaults={"path": "index.html"})
@app.route("/favicon.ico", defaults={"path": "favicon.ico"})
@app.route("/manifest.json", defaults={"path": "manifest.json"})
def serve_root(path: str) -> Any:
    return send_from_directory("mqueryfront/build", path)


@app.route("/api/compactall")
def compact_all():
    redis.rpush("queue-commands", "compact all;")

    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run()
