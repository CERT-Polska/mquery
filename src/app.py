import json
import os
import random
import string
import time

import uvicorn
from fastapi import FastAPI, Body, Query, HTTPException
from starlette.requests import Request
from starlette.responses import Response, FileResponse
from starlette.staticfiles import StaticFiles
from werkzeug.exceptions import NotFound
from zmq import Again

from lib.ursadb import UrsaDb
from lib.yaraparse import parse_yara

from util import make_redis, mquery_version
import config
from typing import Any, Callable, List, Union, cast

from schema import (
    JobsSchema,
    JobSchema,
    TaskSchema,
    RequestQueryMethod,
    QueryRequestSchema,
    QueryResponseSchema,
    ParseResponseSchema,
    DownloadSchema,
    MatchesSchema,
    StatusSchema,
    UserSettingsSchema,
    UserInfoSchema,
    UserAuthSchema,
    BackendStatusSchema,
    BackendStatusDatasetsSchema,
)

redis = make_redis()
app = FastAPI()
db = UrsaDb(config.BACKEND)


@app.middleware("http")
async def add_headers(request: Request, call_next: Callable) -> Response:
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "deny"
    response.headers["Access-Control-Allow-Origin"] = request.client.host
    response.headers[
        "Access-Control-Allow-Headers"
    ] = "cache-control,x-requested-with,content-type,authorization"
    response.headers[
        "Access-Control-Allow-Methods"
    ] = "POST, PUT, GET, OPTIONS, DELETE"
    return response


@app.get("/api/download")
def download(data: DownloadSchema = Body(...)) -> Any:
    file_list = redis.lrange("meta:" + data.job_id, data.ordinal, data.ordinal)

    if not file_list or data.file_path != json.loads(file_list[0])["file"]:
        raise NotFound("No such file in result set.")

    attach_name, ext = os.path.splitext(os.path.basename(data.file_path))
    return FileResponse(data.file_path, filename=attach_name + ext + "_")


@app.post(
    "/api/query",
    response_model=Union[QueryResponseSchema, List[ParseResponseSchema]],
)
def query(
    data: QueryRequestSchema = Body(...)
) -> Union[QueryResponseSchema, List[ParseResponseSchema]]:
    try:
        rules = parse_yara(data.raw_yara)
    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Yara rule parsing failed: {e}"
        )

    if not rules:
        raise HTTPException(status_code=400, detail=f"No rule was specified.")

    if data.method == RequestQueryMethod.parse:
        return [
            ParseResponseSchema(
                rule_name=rule.name,
                rule_author=rule.author,
                is_global=rule.is_global,
                is_private=rule.is_private,
                parsed=rule.parse().query,
            )
            for rule in rules
        ]

    job_hash = "".join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        for _ in range(12)
    )

    job_obj = {
        "status": "new",
        "rule_name": rules[-1].name,
        "rule_author": rules[-1].author,
        "raw_yara": data.raw_yara,
        "submitted": int(time.time()),
        "priority": data.priority,
    }

    if data.taint is not None:
        job_obj["taint"] = data.taint

    redis.hmset("job:" + job_hash, job_obj)
    redis.rpush("queue-search", job_hash)

    return QueryResponseSchema(query_hash=job_hash)


@app.get("/api/matches/{hash}", response_model=MatchesSchema)
def matches(
    hash: str, offset: int = Query(...), limit: int = Query(...)
) -> MatchesSchema:
    p = redis.pipeline(transaction=False)
    p.hgetall("job:" + hash)
    p.lrange("meta:" + hash, offset, offset + limit - 1)
    job, meta = p.execute()

    return MatchesSchema(job=job, matches=[json.loads(m) for m in meta])


@app.get("/api/job/<hash>", response_model=List[JobSchema])
def job_info(hash: str) -> List[JobSchema]:
    return [JobSchema(**x) for x in redis.hgetall("job:" + hash)]


@app.delete("/api/job/{job_id}", response_model=StatusSchema)
def job_cancel(job_id: str) -> StatusSchema:
    redis.hmset("job:" + job_id, {"status": "cancelled"})
    return StatusSchema(status="ok")


@app.get("/api/user/settings", response_model=UserSettingsSchema)
def user_settings() -> UserSettingsSchema:
    return UserSettingsSchema(can_register=True, plugin_name="Redis")


@app.post("/api/user/register", response_model=StatusSchema)
def user_register(auth: UserAuthSchema = Body(...)) -> StatusSchema:
    if auth.username.startswith("a"):
        return StatusSchema(status="ok")
    raise HTTPException(status_code=400, detail="This user already exists")


@app.post("/api/user/login", response_model=StatusSchema)
def user_login(auth: UserAuthSchema = Body(...)) -> StatusSchema:
    if auth.username.startswith("a"):
        return StatusSchema(status="ok")
    raise HTTPException(status_code=400, detail="Wrong password")


@app.get("/api/user/{name}/info", response_model=UserInfoSchema)
def user_info(name: str) -> UserInfoSchema:
    return UserInfoSchema(id=1, name=name)


@app.get("/api/user/{name}/jobs", response_model=List[JobSchema])
def user_jobs(name: str) -> List[JobSchema]:
    return job_statuses()


@app.get("/api/job", response_model=JobsSchema)
def job_statuses() -> JobsSchema:
    jobs = redis.keys("job:*")
    jobs = sorted(
        [dict({"id": job[4:]}, **redis.hgetall(job)) for job in jobs],
        key=lambda o: o.get("submitted"),
        reverse=True,
    )
    return JobsSchema(
        jobs=jobs
    )


@app.get("/api/backend", response_model=BackendStatusSchema)
def backend_status() -> BackendStatusSchema:
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

    return BackendStatusSchema(
        db_alive=db_alive,
        tasks=tasks,
        components={
            "mquery": mquery_version(),
            "ursadb": str(ursadb_version),
        },
    )


@app.get("/api/backend/datasets", response_model=BackendStatusDatasetsSchema)
def backend_status_datasets() -> BackendStatusDatasetsSchema:
    db_alive = True

    try:
        datasets = db.topology().get("result", {}).get("datasets", {})
    except Again:
        db_alive = False
        datasets = {}

    return BackendStatusDatasetsSchema(db_alive=db_alive, datasets=datasets)


@app.get("/query/{path}", include_in_schema=False)
def serve_index(path: str) -> FileResponse:
    return FileResponse("mqueryfront/build/index.html")


@app.get("/recent", include_in_schema=False)
@app.get("/status", include_in_schema=False)
@app.get("/query", include_in_schema=False)
def serve_index_sub() -> FileResponse:
    return FileResponse("mqueryfront/build/index.html")


@app.get("/api/compactall")
def compact_all() -> StatusSchema:
    redis.rpush("queue-commands", "compact all;")
    return StatusSchema(status="ok")


app.mount(
    "/",
    StaticFiles(
        directory=os.path.join(
            os.path.dirname(__file__), "mqueryfront", "build"
        ),
        html=True,
    ),
)


if __name__ == "__main__":
    uvicorn.run(app)
