import os

import uvicorn
from fastapi import FastAPI, Body, Query, HTTPException
from starlette.requests import Request
from starlette.responses import Response, FileResponse
from starlette.staticfiles import StaticFiles
from werkzeug.exceptions import NotFound
from zmq import Again

from lib.ursadb import UrsaDb
from lib.yaraparse import parse_yara

from util import mquery_version
from db import Database, JobId
import config
from typing import Any, Callable, List, Union

from schema import (
    JobsSchema,
    JobSchema,
    RequestQueryMethod,
    QueryRequestSchema,
    QueryResponseSchema,
    ParseResponseSchema,
    MatchesSchema,
    StatusSchema,
    StorageSchema,
    UserSettingsSchema,
    UserInfoSchema,
    UserAuthSchema,
    BackendStatusSchema,
    BackendStatusDatasetsSchema,
    StorageRequestSchema,
    StorageCreateRequestSchema,
)

db = Database()
app = FastAPI()
ursa = UrsaDb(config.BACKEND)


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
def download(job_id: str, ordinal: str, file_path: str) -> Any:
    if not db.job_contains(JobId(job_id), ordinal, file_path):
        raise NotFound("No such file in result set.")

    attach_name, ext = os.path.splitext(os.path.basename(file_path))
    return FileResponse(file_path, filename=attach_name + ext + "_")


@app.post(
    "/api/query",
    response_model=Union[QueryResponseSchema, List[ParseResponseSchema]],
)
def query(
    data: QueryRequestSchema = Body(...),
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

    job = db.create_search_task(
        rules[-1].name,
        rules[-1].author,
        data.raw_yara,
        data.priority,
        data.taint,
    )
    return QueryResponseSchema(query_hash=job.hash)


@app.get("/api/matches/{hash}", response_model=MatchesSchema)
def matches(
    hash: str, offset: int = Query(...), limit: int = Query(...)
) -> MatchesSchema:
    return db.get_job_matches(JobId(hash), offset, limit)


@app.get("/api/job/{job_id}", response_model=JobSchema)
def job_info(job_id: str) -> JobSchema:
    return db.get_job(JobId(job_id))


@app.delete("/api/job/{job_id}", response_model=StatusSchema)
def job_cancel(job_id: str) -> StatusSchema:
    db.cancel_job(JobId(job_id))
    return StatusSchema(status="ok")


@app.get("/api/storage", response_model=List[StorageSchema])
def storage_list() -> List[StorageSchema]:
    return db.get_storages()


@app.post("/api/storage", response_model=StatusSchema)
def storage_add(data: StorageCreateRequestSchema = Body(...)) -> StatusSchema:
    db.create_storage(data.name, data.path)
    return StatusSchema(status="ok")


@app.post("/api/storage/enable", response_model=StatusSchema)
def storage_enable(data: StorageRequestSchema = Body(...)) -> StatusSchema:
    db.enable_storage(data.id)
    return StatusSchema(status="ok")


@app.post("/api/storage/disable", response_model=StatusSchema)
def storage_disable(data: StorageRequestSchema = Body(...)) -> StatusSchema:
    db.disable_storage(data.id)
    return StatusSchema(status="ok")


@app.post("/api/storage/delete", response_model=StatusSchema)
def storage_delete(data: StorageRequestSchema = Body(...)) -> StatusSchema:
    db.delete_storage(data.id)
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
    jobs = [db.get_job(job) for job in db.get_job_ids()]
    jobs = sorted(jobs, key=lambda j: j.submitted, reverse=True)
    return JobsSchema(jobs=jobs)


@app.get("/api/backend", response_model=BackendStatusSchema)
def backend_status() -> BackendStatusSchema:
    db_alive = True
    status = ursa.status()
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
        datasets = ursa.topology().get("result", {}).get("datasets", {})
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
    db.run_command("compact all;")
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
