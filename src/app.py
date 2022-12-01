from lib.ursadb import UrsaDb
import os

import uvicorn  # type: ignore
import config
from fastapi import FastAPI, Body, Query, HTTPException, Depends, Header  # type: ignore
from starlette.requests import Request  # type: ignore
from starlette.responses import Response, FileResponse, StreamingResponse  # type: ignore
from starlette.staticfiles import StaticFiles  # type: ignore
from zmq import Again

from lib.yaraparse import parse_yara

from util import mquery_version
from db import Database, JobId
from typing import Any, Callable, List, Union, Dict, Iterable, Optional
import tempfile
import zipfile
import jwt
import base64
from cryptography.hazmat.primitives import serialization

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
    BackendStatusSchema,
    BackendStatusDatasetsSchema,
    AgentSchema,
    ServerSchema,
)


db = Database(config.REDIS_HOST, config.REDIS_PORT)
app = FastAPI()


class User:
    def __init__(self, token: Optional[Dict]) -> None:
        self.__token = token

    @property
    def is_anonymous(self) -> bool:
        return self.__token is None

    @property
    def name(self) -> str:
        if self.__token is None:
            return "anonymous"
        return self.__token.get("preferred_username", "unknown")

    def roles(self, client_id: Optional[str]) -> List[str]:
        if self.__token is None:
            return []
        try:
            return self.__token["resource_access"][client_id]["roles"]
        except KeyError:
            return []


async def current_user(authorization: Optional[str] = Header(None)) -> User:
    if not authorization:
        return User(None)

    bearer, token = authorization.split()
    if bearer != "Bearer":
        return User(None)

    secret = db.get_mquery_config_key("openid_secret")
    if secret is None:
        return User(None)

    public_key = serialization.load_der_public_key(base64.b64decode(secret))  # type: ignore
    try:
        token_json = jwt.decode(
            token, public_key, algorithms=["RS256"], audience="account"  # type: ignore
        )
    except jwt.ExpiredSignatureError:
        # The signature has expired. Maybe we should raise 401 here, but on the
        # other hand we don't want to raise 401 if auth_enabled is not enabled.
        return User(None)

    return User(token_json)


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


class RoleChecker:
    def __init__(self, allowed_roles: List[str]) -> None:
        self.allowed_roles = allowed_roles

    def __call__(self, user: User = Depends(current_user)):
        auth_enabled = db.get_mquery_config_key("auth_enabled")
        if not auth_enabled or auth_enabled == "false":
            return

        client_id = db.get_mquery_config_key("openid_client_id")
        user_roles = user.roles(client_id)
        auth_default_roles = db.get_mquery_config_key("auth_default_roles")
        if auth_default_roles is None:
            default_roles = []
        else:
            default_roles = [
                role.strip() for role in auth_default_roles.split(",")
            ]
        all_user_roles = list(set(user_roles + default_roles))

        if not any(role in self.allowed_roles for role in all_user_roles):
            message = (
                f"Operation not allowed for user {user.name} "
                f"(user roles: {user_roles}) "
                f"(default roles: {default_roles}) "
                f"(required roles: any of {self.allowed_roles})"
            )
            error_code = 401 if user.is_anonymous else 403
            raise HTTPException(
                status_code=error_code,
                detail=message,
            )


is_admin = RoleChecker(["admin"])
is_user = RoleChecker(["user"])


# Admin-only routes (when user permissions are configured).
# Non-admins can't use them, and shouldn't see them in the UI.


@app.get(
    "/api/config",
    response_model=List[ConfigSchema],
    tags=["internal"],
    dependencies=[Depends(is_admin)],
)
def config_list() -> List[ConfigSchema]:
    """
    Returns the current database configuration.

    This endpoint is not stable and may be subject to change in the future.
    """
    return db.get_config()


@app.post(
    "/api/compact",
    response_model=StatusSchema,
    tags=["internal"],
    dependencies=[Depends(is_admin)],
)
def compact_files() -> StatusSchema:
    """
    Broadcasts compact command to all ursadb instances. This uses `compact all;`
    subcommand (which is more intuitive because it always compacts), instead of the
    recommended `compact smart;` which ignores useless merges. Because of this,
    and also because of lack of control, this it's not recommended for advanced
    users - see documentation and `compactall.py` script to learn more.

    This still won't merge datasets of different types or with different tags,
    and will silently do nothing in such cases.

    This endpoint is not stable and may be subject to change in the future.
    """
    db.broadcast_command(f"compact all;")
    return StatusSchema(status="ok")


@app.post(
    "/api/config/edit",
    response_model=StatusSchema,
    tags=["internal"],
    dependencies=[Depends(is_admin)],
)
def config_edit(data: RequestConfigEdit = Body(...)) -> StatusSchema:
    """
    Change a given configuration key to a specified value.

    This endpoint is not stable and may be subject to change in the future.
    """
    db.set_config_key(data.plugin, data.key, data.value)
    return StatusSchema(status="ok")


# Standard authenticated routes (when user permissions are configured).
# Accessible for every logged in user (permission: "reader")


@app.get("/api/download", tags=["stable"], dependencies=[Depends(is_user)])
def download(job_id: str, ordinal: int, file_path: str) -> Response:
    """
    Sends a file from given `file_path`. This path should come from
    results of one of the previous searches.

    This endpoint needs `job_id` that found the specified file, and `ordinal`
    (index of the file in that job), to ensure that user can't download
    arbitrary files (for example "/etc/passwd").
    """
    if not db.job_contains(JobId(job_id), ordinal, file_path):
        return Response("No such file in result set.", status_code=404)

    attach_name, ext = os.path.splitext(os.path.basename(file_path))
    return FileResponse(file_path, filename=attach_name + ext + "_")


@app.get("/api/download/hashes/{hash}", dependencies=[Depends(is_user)])
def download_hashes(hash: str) -> Response:
    """Returns a list of job matches as a sha256 strings joined with newlines"""

    hashes = "\n".join(
        d["meta"]["sha256"]["display_text"]
        for d in db.get_job_matches(JobId(hash)).matches
    )
    return Response(hashes + "\n")


def zip_files(matches: List[Dict[Any, Any]]) -> Iterable[bytes]:
    with tempfile.NamedTemporaryFile() as writer:
        with open(writer.name, "rb") as reader:
            with zipfile.ZipFile(writer, mode="w") as zipwriter:
                for match in matches:
                    sha256 = match["meta"]["sha256"]["display_text"]
                    zipwriter.write(match["file"], sha256)
                    yield reader.read()
            writer.flush()
            yield reader.read()


@app.get("/api/download/files/{hash}", dependencies=[Depends(is_user)])
async def download_files(hash: str) -> StreamingResponse:
    matches = db.get_job_matches(JobId(hash)).matches
    return StreamingResponse(zip_files(matches))


@app.post(
    "/api/query",
    response_model=Union[QueryResponseSchema, List[ParseResponseSchema]],
    tags=["stable"],
    dependencies=[Depends(is_user)],
)
def query(
    data: QueryRequestSchema = Body(...),
) -> Union[QueryResponseSchema, List[ParseResponseSchema]]:
    """
    Starts a new search. Response will contain a new job ID that can be used
    to check the job status and download matched files.
    """
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

    if not data.taints:
        data.taints = []

    job = db.create_search_task(
        rules[-1].name,
        rules[-1].author,
        data.raw_yara,
        data.priority,
        data.files_limit or 0,
        data.reference or "",
        data.taints,
        list(active_agents.keys()),
    )
    return QueryResponseSchema(query_hash=job.hash)


@app.get(
    "/api/matches/{hash}",
    response_model=MatchesSchema,
    tags=["stable"],
    dependencies=[Depends(is_user)],
)
def matches(
    hash: str, offset: int = Query(...), limit: int = Query(...)
) -> MatchesSchema:
    """
    Returns a list of matched files, along with metadata tags and other
    useful information. Results from this query can be used to download files
    using the `/download` endpoint.
    """
    return db.get_job_matches(JobId(hash), offset, limit)


@app.get(
    "/api/job/{job_id}",
    response_model=JobSchema,
    tags=["stable"],
    dependencies=[Depends(is_user)],
)
def job_info(job_id: str) -> JobSchema:
    """
    Returns a metadata for a single job. May be useful for monitoring
    a job progress.
    """
    return db.get_job(JobId(job_id))


@app.delete(
    "/api/job/{job_id}",
    response_model=StatusSchema,
    tags=["stable"],
    dependencies=[Depends(is_user)],
)
def job_cancel(job_id: str) -> StatusSchema:
    """
    Cancels the job with a provided `job_id`.
    """
    db.cancel_job(JobId(job_id))
    return StatusSchema(status="ok")


@app.get(
    "/api/job",
    response_model=JobsSchema,
    tags=["stable"],
    dependencies=[Depends(is_user)],
)
def job_statuses() -> JobsSchema:
    """
    Returns statuses of all the jobs in the system. May take some time (> 1s)
    when there are a lot of them.
    """
    jobs = [db.get_job(job) for job in db.get_job_ids()]
    jobs = sorted(jobs, key=lambda j: j.submitted, reverse=True)
    jobs = [j for j in jobs if j.status != "removed"]
    return JobsSchema(jobs=jobs)


@app.post(
    "/api/index",
    response_model=StatusSchema,
    tags=["internal"],
    dependencies=[Depends(is_user)],
)
def reindex_files() -> StatusSchema:
    """
    Reindex files in the configured default directory.

    There are no server-side checks to avoid indexing multiple times at the
    same time, care should be taken when using it from user scripts.
    This is also not very efficient for large datasets - take a look at
    the documentation for indexing and `index.py` script to learn more.

    This endpoint is not stable and may be subject to change in the future.
    """
    if config.INDEX_DIR is not None:
        types = "[gram3, text4, wide8, hash4]"
        db.broadcast_command(f'index "{config.INDEX_DIR}" with {types};')
    return StatusSchema(status="ok")


@app.get(
    "/api/backend",
    response_model=BackendStatusSchema,
    tags=["internal"],
    dependencies=[Depends(is_admin)],
)
def backend_status() -> BackendStatusSchema:
    """
    Returns the current status of backend services, and returns it. Intended to
    be used by the webpage.

    This endpoint is not stable and may be subject to change in the future.
    """
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

    return BackendStatusSchema(
        agents=agents,
        components=components,
    )


@app.get(
    "/api/backend/datasets",
    response_model=BackendStatusDatasetsSchema,
    tags=["internal"],
    dependencies=[Depends(is_user)],
)
def backend_status_datasets() -> BackendStatusDatasetsSchema:
    """
    Returns a combined list of datasets from all agents.

    Caveat: In case of collision of dataset ids when there are multiple agents,
    this API will only return one dataset per colliding ID. Collision is
    extremally unlikely though and it shouldn't be a problem in the real world.

    This endpoint is not stable and may be subject to change in the future.
    """
    datasets: Dict[str, int] = {}
    for agent_spec in db.get_active_agents().values():
        try:
            ursa = UrsaDb(agent_spec.ursadb_url)
            datasets.update(ursa.topology()["result"]["datasets"])
        except Again:
            pass

    return BackendStatusDatasetsSchema(datasets=datasets)


@app.delete(
    "/api/query/{job_id}",
    response_model=StatusSchema,
    dependencies=[Depends(is_user)],
)
def query_remove(job_id: str) -> StatusSchema:
    db.remove_query(JobId(job_id))
    return StatusSchema(status="ok")


# Permissionless routes.
# 1. Static routes are always publicly accessible without authorisation.
# 2. /api/server is a special route always accessible for everyone.


@app.get("/api/server", response_model=ServerSchema, tags=["stable"])
def server() -> ServerSchema:
    return ServerSchema(
        version=mquery_version(),
        auth_enabled=db.get_mquery_config_key("auth_enabled"),
        openid_url=db.get_mquery_config_key("openid_url"),
        openid_client_id=db.get_mquery_config_key("openid_client_id"),
    )


@app.get("/query/{path}", include_in_schema=False)
def serve_index(path: str) -> FileResponse:
    return FileResponse("mqueryfront/build/index.html")


@app.get("/recent", include_in_schema=False)
@app.get("/status", include_in_schema=False)
@app.get("/query", include_in_schema=False)
@app.get("/config", include_in_schema=False)
@app.get("/auth", include_in_schema=False)
def serve_index_sub() -> FileResponse:
    # Static routes are always publicly accessible without authorisation.
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
