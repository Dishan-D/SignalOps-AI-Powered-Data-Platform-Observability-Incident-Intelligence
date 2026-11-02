"""SignalOps operational API.

    uvicorn signalops.api.app:app --host 127.0.0.1 --port 8000

Every route is a thin adapter over :mod:`signalops.services`; none runs SQL of
its own. All operational routes are read-only. ``/api/ops/health`` and
``/api/ops/metrics`` never touch the LLM provider; investigations run on a
background pool and are polled by job id.

Errors share one envelope::

    {"error": {"code": "...", "message": "...", "source": "...?"}}
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hmac
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from fastapi import Depends, FastAPI, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response

from forensics.common.config import ConfigError
from forensics.common.logging import configure_logging, correlation_scope, get_logger
from signalops import __version__
from signalops.config import Settings
from signalops.investigation import (
    InvestigationJob,
    InvestigationJobs,
    InvestigationQueueFull,
    InvestigationRequest,
    Investigator,
)
from signalops.investigation.provider import LLMProvider, ProviderError, build_provider
from signalops.models import (
    DetectionDetail,
    DetectionPage,
    DlqSummary,
    HostTimeline,
    IncidentCandidate,
    IncidentList,
    LedgerStatus,
    PipelineHealth,
    PipelineMetrics,
)
from signalops.retrieval.runbooks import RunbookHit, RunbookIndex
from signalops.services import OpsServices
from signalops.services.detections import NotFoundError
from signalops.services.health import is_ready
from signalops.services.incidents import validate_incident_id
from signalops.sources.errors import DataSourceError

logger = get_logger(__name__, component="signalops-api")

REQUEST_TIMEOUT_SECONDS = 30.0
WINDOW = Query(60, ge=5, le=10080, description="Look-back window in minutes")


def _error(status: int, code: str, message: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status,
                        content={"error": {"code": code, "message": message, **extra}})


def create_app(
    settings: Settings | None = None,
    *,
    services: OpsServices | None = None,
    runbooks: RunbookIndex | None = None,
    provider_factory: Callable[[], LLMProvider] | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    if not settings.api_key and settings.environment != "local":
        raise ConfigError("SIGNALOPS_API_KEY must be set when APP_ENV is not 'local'")
    services = services or OpsServices.build(settings)
    runbooks = runbooks or RunbookIndex.load(settings.runbook_dir)
    factory = provider_factory or (lambda: build_provider(settings.llm))
    investigator = Investigator(services, runbooks, factory, settings.llm)
    jobs = InvestigationJobs(investigator)

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        jobs.shutdown()

    app = FastAPI(
        title="SignalOps Operational API",
        version=__version__,
        description="Read-only operational intelligence over the forensics streaming pipeline.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.services = services
    app.state.runbooks = runbooks
    app.state.jobs = jobs
    app.state.provider_factory = factory

    if not settings.api_key:
        logger.warning("SIGNALOPS_API_KEY not set; API is unauthenticated (local only)")

    # -- middleware ------------------------------------------------------------

    @app.middleware("http")
    async def request_context(request: Request,
                              call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        started = time.perf_counter()
        with correlation_scope(request_id):
            try:
                response = await asyncio.wait_for(call_next(request), REQUEST_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                response = _error(504, "timeout",
                                  f"request exceeded {REQUEST_TIMEOUT_SECONDS:.0f}s")
            response.headers["x-request-id"] = request_id
            logger.info("request", extra={
                "method": request.method, "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            })
        return response

    # -- error handlers --------------------------------------------------------

    @app.exception_handler(DataSourceError)
    async def _source_error(_: Request, exc: DataSourceError) -> JSONResponse:
        return _error(503, "dependency_unavailable" if exc.unavailable else "dependency_error",
                      exc.message, source=exc.source)

    @app.exception_handler(NotFoundError)
    async def _not_found(_: Request, exc: NotFoundError) -> JSONResponse:
        return _error(404, "not_found", str(exc))

    @app.exception_handler(ValueError)
    async def _bad_value(_: Request, exc: ValueError) -> JSONResponse:
        return _error(422, "invalid_request", str(exc))

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        details = [{"loc": list(e.get("loc", [])), "message": e.get("msg", "")}
                   for e in exc.errors()[:10]]
        return _error(422, "invalid_request", "request validation failed", details=details)

    # -- auth ------------------------------------------------------------------

    def require_api_key(request: Request) -> None:
        if not settings.api_key:
            return
        supplied = request.headers.get("x-api-key", "")
        if not hmac.compare_digest(supplied.encode(), settings.api_key.encode()):
            raise _Unauthorized()

    @app.exception_handler(_Unauthorized)
    async def _unauthorized(_: Request, __: _Unauthorized) -> JSONResponse:
        return _error(401, "unauthorized", "missing or invalid X-API-Key")

    auth = [Depends(require_api_key)]

    # -- probes (unauthenticated, no dependencies beyond Postgres) --------------

    @app.get("/api/ops/livez", tags=["probes"])
    def livez() -> dict[str, str]:
        """Process liveness only."""
        return {"status": "alive"}

    @app.get("/api/ops/readyz", tags=["probes"])
    def readyz() -> JSONResponse:
        """Ready when the evidence store is reachable."""
        ok, detail = is_ready(services.db)
        return JSONResponse(status_code=200 if ok else 503,
                            content={"status": "ready" if ok else "not_ready", "detail": detail})

    # -- operational reads -----------------------------------------------------

    @app.get("/api/ops/health", response_model=PipelineHealth, dependencies=auth, tags=["ops"])
    def health() -> PipelineHealth:
        """Component health (postgres, kafka, spark, detector, ledger). LLM-independent."""
        return services.cached_health()

    @app.get("/api/ops/metrics", response_model=PipelineMetrics, dependencies=auth, tags=["ops"])
    def metrics(window_minutes: int = WINDOW) -> PipelineMetrics:
        return services.cached_metrics(window_minutes)

    @app.get("/api/ops/incidents", response_model=IncidentList, dependencies=auth, tags=["ops"])
    def incidents(window_minutes: int = WINDOW) -> IncidentList:
        """Rule-derived investigation candidates (not confirmed incidents)."""
        return services.cached_incidents(window_minutes)

    @app.get("/api/ops/incidents/{incident_id}", response_model=IncidentCandidate,
             dependencies=auth, tags=["ops"])
    def incident(incident_id: str = Path(max_length=300),
                 window_minutes: int = WINDOW) -> IncidentCandidate:
        validate_incident_id(incident_id)
        found = next((c for c in services.cached_incidents(window_minutes).candidates
                      if c.incident_id == incident_id), None)
        if found is None:
            raise NotFoundError(f"incident candidate {incident_id!r} is not active in the last "
                                f"{window_minutes} minutes")
        return found

    @app.get("/api/ops/dlq/summary", response_model=DlqSummary, dependencies=auth, tags=["ops"])
    def dlq_summary(window_minutes: int = WINDOW,
                    sample_per_partition: int = Query(50, ge=1, le=200)) -> DlqSummary:
        return services.cached_dlq(window_minutes, sample_per_partition)

    @app.get("/api/ops/detections", response_model=DetectionPage, dependencies=auth, tags=["ops"])
    def detections(window_minutes: int = Query(1440, ge=5, le=10080),
                   flagged_only: bool = True,
                   host: str | None = Query(None, max_length=253),
                   limit: int = Query(50, ge=1, le=500),
                   offset: int = Query(0, ge=0, le=100_000)) -> DetectionPage:
        return services.detections.list(window_minutes=window_minutes, flagged_only=flagged_only,
                                        host_name=host, limit=limit, offset=offset)

    @app.get("/api/ops/detections/{detection_id}", response_model=DetectionDetail,
             dependencies=auth, tags=["ops"])
    def detection(detection_id: int = Path(ge=1),
                  max_events: int = Query(50, ge=1, le=200)) -> DetectionDetail:
        return services.detections.detail(detection_id, max_events=max_events)

    @app.get("/api/ops/hosts/{host_id}/timeline", response_model=HostTimeline,
             dependencies=auth, tags=["ops"])
    def host_timeline(host_id: str = Path(max_length=253, description="host name"),
                      window_minutes: int = WINDOW,
                      end: dt.datetime | None = None,
                      limit: int = Query(200, ge=1, le=500)) -> HostTimeline:
        return services.detections.host_timeline(host_id, window_minutes=window_minutes,
                                                 end=end, limit=limit)

    @app.get("/api/ops/ledger/status", response_model=LedgerStatus, dependencies=auth, tags=["ops"])
    def ledger_status() -> LedgerStatus:
        return services.cached_ledger()

    @app.get("/api/ops/runbooks/search", response_model=list[RunbookHit], dependencies=auth,
             tags=["runbooks"])
    def runbook_search(q: str = Query(min_length=1, max_length=500),
                       limit: int = Query(3, ge=1, le=10)) -> list[RunbookHit] | JSONResponse:
        if not runbooks.available:
            return _error(503, "runbooks_unavailable", "; ".join(runbooks.errors or ["no runbooks"]))
        return runbooks.search(q, limit=limit)

    # -- investigations --------------------------------------------------------

    def provider_status() -> dict[str, Any]:
        try:
            provider = factory()
        except ProviderError as exc:
            return {"enabled": False, "provider": settings.llm.provider, "reason": str(exc)}
        return {"enabled": True, "provider": provider.name, "model": provider.model,
                "uses_llm": provider.uses_llm}

    @app.get("/api/ops/investigations", dependencies=auth, tags=["investigations"])
    def investigations_status() -> dict[str, Any]:
        """Whether investigations are available, and with which provider."""
        return {"provider": provider_status()}

    @app.post("/api/ops/investigate", status_code=202, response_model=InvestigationJob,
              dependencies=auth, tags=["investigations"])
    def investigate(request: InvestigationRequest) -> InvestigationJob | JSONResponse:
        """Start an investigation; poll GET /api/ops/investigations/{job_id}."""
        status = provider_status()
        if not status["enabled"]:
            return _error(503, "investigations_unavailable", status["reason"])
        incident = None
        if request.incident_id:
            incident = services.incidents.get(request.incident_id, request.window_minutes)
            if incident is None:
                return _error(404, "not_found",
                              f"incident candidate {request.incident_id!r} is not active in the last "
                              f"{request.window_minutes} minutes")
        try:
            return jobs.submit(request, incident)
        except InvestigationQueueFull as exc:
            return _error(429, "too_many_investigations", str(exc))

    @app.get("/api/ops/investigations/{job_id}", response_model=InvestigationJob,
             dependencies=auth, tags=["investigations"])
    def investigation(job_id: str = Path(pattern=r"^[0-9a-f]{32}$")) -> InvestigationJob:
        job = jobs.get(job_id)
        if job is None:
            raise NotFoundError(f"investigation {job_id} not found (jobs are kept in memory)")
        return job

    # -- Slack -----------------------------------------------------------------

    from signalops.slack.commands import create_slack_router

    app.include_router(create_slack_router(settings, services, runbooks, jobs, provider_status))

    return app


class _Unauthorized(Exception):
    pass


def _build_default() -> FastAPI:
    settings = Settings.from_env()
    configure_logging(service="signalops-api", environment=settings.environment,
                      level=settings.log_level)
    return create_app(settings)


def __getattr__(name: str) -> Any:
    # `uvicorn signalops.api.app:app` builds the app lazily, so importing this
    # module (tests, tooling) never reads the environment or opens connections.
    if name == "app":
        value = _build_default()
        globals()["app"] = value
        return value
    raise AttributeError(name)
