from lib.ursadb import UrsaDb
import os
from threading import Lock

import uvicorn  # type: ignore
from config import app_config
from fastapi import (
    FastAPI,
    Body,
    Query,
    HTTPException,
    Depends,
    Header,
    BackgroundTasks,
)  # type: ignore
from starlette.requests import Request  # type: ignore
from starlette.responses import Response, FileResponse, StreamingResponse  # type: ignore
from starlette.staticfiles import StaticFiles  # type: ignore
from zmq import Again

from lib.yaraparse import parse_yara

from util import mquery_version
from db import Database
from typing import Any, Callable, List, Union, Dict, Iterable, Optional
import tempfile
import zipfile
import jwt
import base64
from cryptography.hazmat.primitives import serialization
from plugins import PluginManager

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


db = Database(app_config.redis.host, app_config.redis.port)
app = FastAPI()
plugins = PluginManager(app_config.mquery.plugins, db)
plugin_lock = Lock()


def use_plugins(background: BackgroundTasks) -> None:
    """Acquires a plugin_lock, and releases it after cleanup and returning a response.
    This function should be called by every API endpoint that uses plugins.

    This lock is necessary, because nothing in the plugins API makes it obvious that
    they should be thread-safe - so we assume that they're not.
    """

    def release_and_cleanup():
        try:
            # Hopefully this won't crash...
            plugins.cleanup()
        finally:
            # ...but just in case it does, we absolutely have to release the lock.
            plugin_lock.release()

    plugin_lock.acquire()
    background.add_task(release_and_cleanup)


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
    auth_enabled = db.get_mquery_config_key("auth_enabled")
    if not auth_enabled or auth_enabled == "false":
        return User(None)

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
    except jwt.InvalidTokenError:
        # A generic signature error. Maybe we should raise 401 here, but on the
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
    def __init__(self, need_permissions: List[str]) -> None:
        self.need_permissions = need_permissions

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
        all_roles = list(set(user_roles + default_roles))
        all_roles = sum((expand_role(role) for role in all_roles), [])

        if not any(role in self.need_permissions for role in all_roles):
            message = (
                f"Operation not allowed for user {user.name} "
                f"(user effective roles: {user_roles}) "
                f"(required roles: any of {self.need_permissions})"
            )
            error_code = 401 if user.is_anonymous else 403
            raise HTTPException(
                status_code=error_code,
                detail=message,
            )


# See docs/users.md for documentation on the permission model.
is_admin = RoleChecker(["admin"])
is_user = RoleChecker(["user"])
can_view_queries = RoleChecker(["can_view_queries"])
can_manage_queries = RoleChecker(["can_manage_queries"])
can_list_queries = RoleChecker(["can_list_queries"])
can_download_files = RoleChecker(["can_download_files"])


def expand_role(role: str) -> List[str]:
    """Some roles imply other roles or permissions. For example, admin role
    also gives permissions for all user permissions."""
    role_implications = {
        "admin": ["user"],
        "user": [
            "can_view_queries",
            "can_manage_queries",
            "can_list_queries",
            "can_download_files",
        ],
    }
    implied_roles = [role]
    for subrole in role_implications.get(role, []):
        implied_roles += expand_role(subrole)
    return implied_roles


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


@app.get(
    "/api/backend",
    response_model=BackendStatusSchema,
    tags=["internal"],
    dependencies=[Depends(is_admin)],
)
def backend_status() -> BackendStatusSchema:
    """
    Gets the current status of backend services, and returns it. Intended to
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
    dependencies=[Depends(is_admin)],
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


# Standard authenticated routes (when user permissions are configured).
# Accessible for every logged in user (permission: "reader")


@app.get(
    "/api/download",
    tags=["stable"],
    dependencies=[Depends(can_download_files), Depends(use_plugins)],
)
def download(job_id: str, ordinal: int, file_path: str) -> Response:
    """
    Sends a file from given `file_path`. This path should come from
    results of one of the previous searches.

    This endpoint needs `job_id` that found the specified file, and `ordinal`
    (index of the file in that job), to ensure that user can't download
    arbitrary files (for example "/etc/passwd").
    """
    if not db.job_contains(job_id, ordinal, file_path):
        return Response("No such file in result set.", status_code=404)

    attach_name, ext = os.path.splitext(os.path.basename(file_path))
    final_path = plugins.filter(file_path)
    if final_path is None:
        raise RuntimeError(
            "Unexpected: trying to download a file excluded by filters"
        )

    return FileResponse(
        final_path,
        filename=attach_name + ext + "_",
    )


@app.get(
    "/api/download/hashes/{job_id}", dependencies=[Depends(can_view_queries)]
)
def download_hashes(job_id: str) -> Response:
    """Returns a list of job matches as a sha256 strings joined with newlines"""

    hashes = "\n".join(
        d["meta"]["sha256"]["display_text"]
        for d in db.get_job_matches(job_id).matches
    )
    return Response(hashes + "\n")


def zip_files(matches: List[Dict[Any, Any]]) -> Iterable[bytes]:
    with tempfile.NamedTemporaryFile() as writer:
        with open(writer.name, "rb") as reader:
            with zipfile.ZipFile(writer, mode="w") as zipwriter:
                for match in matches:
                    sha256 = match["meta"]["sha256"]["display_text"]
                    file_path = plugins.filter(match["file"])
                    if file_path is None:
                        raise RuntimeError("Zipped file excluded by filters")
                    zipwriter.write(file_path, sha256)
                    yield reader.read()
            writer.flush()
            yield reader.read()


@app.get(
    "/api/download/files/{job_id}",
    dependencies=[Depends(is_user), Depends(can_download_files)],
)
async def download_files(job_id: str) -> StreamingResponse:
    matches = db.get_job_matches(job_id).matches
    return StreamingResponse(zip_files(matches))


@app.post(
    "/api/query",
    response_model=Union[QueryResponseSchema, List[ParseResponseSchema]],  # type: ignore
    tags=["stable"],
    dependencies=[Depends(can_manage_queries)],
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
        raise HTTPException(status_code=400, detail="No rule was specified.")

    if data.method == RequestQueryMethod.parse:
        return [
            ParseResponseSchema(
                rule_name=rule.name,
                rule_author=rule.author,
                is_global=rule.is_global,
                is_private=rule.is_private,
                is_degenerate=rule.parse().is_degenerate,
                parsed=rule.parse().query,
            )
            for rule in rules
        ]

    degenerate_rules = [r.name for r in rules if r.parse().is_degenerate]
    allow_slow = db.get_mquery_config_key("query_allow_slow") == "true"
    if degenerate_rules and not (allow_slow and data.force_slow_queries):
        if allow_slow:
            # Warning: "You can force a slow query" literal is used to
            # pattern match on the error message in the frontend.
            help_message = "You can force a slow query if you want."
        else:
            help_message = "This is not allowed by this server."
        degenerate_rule_names = ", ".join(degenerate_rules)
        doc_url = "https://cert-polska.github.io/mquery/docs/goodyara.html"
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid query. Some of the rules require a full Yara scan of"
                "every indexed file. "
                f"{help_message} "
                f"Slow rules: {degenerate_rule_names}. "
                f"Read {doc_url} for more details."
            ),
        )

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
        data.files_limit or 0,
        data.reference or "",
        data.taints,
        list(active_agents.keys()),
    )
    return QueryResponseSchema(query_hash=job)


@app.get(
    "/api/matches/{job_id}",
    response_model=MatchesSchema,
    tags=["stable"],
    dependencies=[Depends(can_view_queries)],
)
def matches(
    job_id: str, offset: int = Query(...), limit: int = Query(...)
) -> MatchesSchema:
    """
    Returns a list of matched files, along with metadata tags and other
    useful information. Results from this query can be used to download files
    using the `/download` endpoint.
    """
    return db.get_job_matches(job_id, offset, limit)


@app.get(
    "/api/job/{job_id}",
    response_model=JobSchema,
    tags=["stable"],
    dependencies=[Depends(can_view_queries)],
)
def job_info(job_id: str) -> JobSchema:
    """
    Returns a metadata for a single job. May be useful for monitoring
    a job progress.
    """
    return db.get_job(job_id)


@app.delete(
    "/api/job/{job_id}",
    response_model=StatusSchema,
    tags=["stable"],
    dependencies=[Depends(can_manage_queries)],
)
def job_cancel(job_id: str) -> StatusSchema:
    """
    Cancels the job with a provided `job_id`.
    """
    db.cancel_job(job_id)
    return StatusSchema(status="ok")


@app.get(
    "/api/job",
    response_model=JobsSchema,
    tags=["stable"],
    dependencies=[Depends(can_list_queries)],
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


@app.delete(
    "/api/query/{job_id}",
    response_model=StatusSchema,
    dependencies=[Depends(can_manage_queries)],
)
def query_remove(job_id: str) -> StatusSchema:
    db.remove_query(job_id)
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
        about=app_config.mquery.about
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
