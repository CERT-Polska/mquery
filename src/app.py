from lib.ursadb import UrsaDb
import os

import uvicorn
import config
from fastapi import FastAPI, Body, Query, HTTPException
from starlette.requests import Request
from starlette.responses import Response, FileResponse
from starlette.staticfiles import StaticFiles
from werkzeug.exceptions import NotFound
from zmq import Again

from lib.yaraparse import parse_yara

from util import mquery_version
from db import Database, JobId
from typing import Any, Callable, List, Union

from schema import (
    JobsSchema,
    JobSchema,
    RequestConfigEdit,
    RequestQueryMethod,
    QueryRequestSchema,
    QueryResponseSchema,
    ParseResponseSchema,
    MatchesSchema,
    StatusSchema,
    ConfigSchema,
    UserSettingsSchema,
    UserInfoSchema,
    UserAuthSchema,
    BackendStatusSchema,
    BackendStatusDatasetsSchema,
    AgentSchema,
)

db = Database(config.REDIS_HOST, config.REDIS_PORT)
app = FastAPI()


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

    active_agents = db.get_active_agents()

    for agent, agent_spec in active_agents.items():
        missing = set(data.required_plugins).difference(
            agent_spec.active_plugins
        )
        if missing:
            raise HTTPException(
                status_code=409,
                detail=f"Agent {agent} doesn't support "
                f"required plugins: {', '.join(missing)}",
            )

    job = db.create_search_task(
        rules[-1].name,
        rules[-1].author,
        data.raw_yara,
        data.priority,
        data.taint,
        list(active_agents.keys()),
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


@app.get("/api/config", response_model=List[ConfigSchema])
def config_list() -> List[ConfigSchema]:
    return db.get_plugins_config()


@app.post("/api/config/edit", response_model=StatusSchema)
def config_edit(data: RequestConfigEdit = Body(...)) -> StatusSchema:
    db.set_plugin_configuration_key(data.plugin, data.key, data.value)
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
    agents = []
    components = {
        "mquery": mquery_version(),
    }
    for name, agent_spec in db.get_active_agents().items():
        try:
            ursa = UrsaDb(agent_spec.ursadb_url)
            status = ursa.status()
            tasks = status["result"]["tasks"]
            ursadb_version = status["result"]["ursadb_version"]
            agents.append(
                AgentSchema(
                    name=name, alive=True, tasks=tasks, spec=agent_spec
                )
            )
            components[f"ursadb ({name})"] = ursadb_version
        except Again:
            agents.append(
                AgentSchema(name=name, alive=False, tasks=[], spec=agent_spec)
            )
            components[f"ursadb ({name})"] = "unknown"

    return BackendStatusSchema(agents=agents, components=components,)


@app.get("/api/backend/datasets", response_model=BackendStatusDatasetsSchema)
def backend_status_datasets() -> BackendStatusDatasetsSchema:
    datasets = {}
    for agent_spec in db.get_active_agents().values():
        try:
            ursa = UrsaDb(agent_spec.ursadb_url)
            datasets.update(ursa.topology()["result"]["datasets"])
        except Again:
            pass

    return BackendStatusDatasetsSchema(datasets=datasets)


@app.get("/query/{path}", include_in_schema=False)
def serve_index(path: str) -> FileResponse:
    return FileResponse("mqueryfront/build/index.html")


@app.get("/recent", include_in_schema=False)
@app.get("/status", include_in_schema=False)
@app.get("/query", include_in_schema=False)
def serve_index_sub() -> FileResponse:
    return FileResponse("mqueryfront/build/index.html")


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
