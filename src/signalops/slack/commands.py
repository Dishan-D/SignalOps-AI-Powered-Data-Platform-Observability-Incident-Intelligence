"""``/ops`` slash command for Slack.

    /ops health                 component health
    /ops incidents              current incident candidates          (allow-listed users)
    /ops investigate <id>       start an investigation               (allow-listed users)
    /ops runbook <query>        search the runbooks
    /ops help

Protocol, per Slack's slash-command contract:

* Every request is verified with the signing secret (``slack_sdk``'s
  ``SignatureVerifier``: HMAC-SHA256 over ``v0:{timestamp}:{body}``, requests
  older than five minutes rejected). Unsigned or stale requests get 401.
* The request is acknowledged immediately (well inside Slack's 3-second
  deadline) and the real answer is posted to ``response_url`` from a background
  task. Investigations post again when the job finishes.
* ``response_url`` must be an https URL on ``hooks.slack.com`` — the API never
  posts to an arbitrary host supplied in a request body.
* Retries and duplicates (same ``trigger_id``, or an ``X-Slack-Retry-Num``
  header) are acknowledged without being processed twice.

Every command calls the same services as the API. The integration is disabled
(404) unless ``SLACK_SIGNING_SECRET`` is set.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlparse

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse

from forensics.common.logging import get_logger
from signalops.config import Settings
from signalops.investigation import InvestigationJobs, InvestigationQueueFull, InvestigationRequest
from signalops.investigation.schemas import InvestigationJob
from signalops.models import Status
from signalops.retrieval.runbooks import RunbookIndex
from signalops.services import OpsServices
from signalops.services.incidents import validate_incident_id
from signalops.sources.errors import DataSourceError

logger = get_logger(__name__, component="signalops-slack")

PostFn = Callable[[str, dict[str, Any]], None]

STATUS_EMOJI = {
    Status.healthy: ":large_green_circle:", Status.degraded: ":large_yellow_circle:",
    Status.unhealthy: ":red_circle:", Status.unavailable: ":black_circle:",
    Status.unknown: ":white_circle:",
}

HELP = (
    "*SignalOps* commands:\n"
    "• `/ops health` — pipeline component health\n"
    "• `/ops incidents` — current incident candidates\n"
    "• `/ops investigate <incident_id>` — start an investigation\n"
    "• `/ops runbook <query>` — search the runbooks"
)

SENSITIVE_COMMANDS = frozenset({"incidents", "investigate"})


def default_post(url: str, payload: dict[str, Any]) -> None:
    import httpx

    response = httpx.post(url, json=payload, timeout=5.0, follow_redirects=False)
    response.raise_for_status()


def is_slack_response_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname == "hooks.slack.com" and not parsed.port


class _Seen:
    """Bounded TTL set for duplicate suppression."""

    def __init__(self, ttl_seconds: float = 600, capacity: int = 2048) -> None:
        self._ttl, self._capacity = ttl_seconds, capacity
        self._items: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def add(self, key: str) -> bool:
        """True if newly added, False if seen within the TTL."""
        now = time.monotonic()
        with self._lock:
            while self._items and next(iter(self._items.values())) < now - self._ttl:
                self._items.popitem(last=False)
            if key in self._items:
                return False
            self._items[key] = now
            while len(self._items) > self._capacity:
                self._items.popitem(last=False)
            return True


def _ephemeral(text: str) -> dict[str, Any]:
    return {"response_type": "ephemeral", "text": text}


# --------------------------------------------------------------------------- #
# Formatting                                                                   #
# --------------------------------------------------------------------------- #

def format_health(services: OpsServices) -> str:
    health = services.cached_health()
    lines = [f"{STATUS_EMOJI[health.status]} *Pipeline {health.status.value}* "
             f"(checked {health.checked_at:%H:%M:%S} UTC)"]
    lines += [f"{STATUS_EMOJI[c.status]} *{c.name}* — {c.status.value}: {c.detail[:200]}"
              for c in health.components]
    return "\n".join(lines)


def format_incidents(services: OpsServices) -> str:
    incidents = services.cached_incidents(60)
    if not incidents.candidates:
        text = "No incident candidates in the last 60 minutes."
    else:
        text = "*Incident candidates (last 60 min)* — rule matches, not confirmed incidents\n" + "\n".join(
            f"• `{c.incident_id}` [{c.severity.value}] {c.title}" for c in incidents.candidates[:10])
    if incidents.rules_skipped:
        text += "\n_Rules not evaluated:_ " + "; ".join(incidents.rules_skipped)[:400]
    return text


def format_runbooks(runbooks: RunbookIndex, query: str) -> str:
    if not runbooks.available:
        return "Runbook index unavailable."
    hits = runbooks.search(query, limit=3)
    if not hits:
        return f"No runbook sections matched `{query[:80]}`."
    return "\n\n".join(f"*{h.title}* — _{h.section}_ (`{h.source}`)\n{h.excerpt[:300]}" for h in hits)


def format_report(job: InvestigationJob) -> str:
    if job.status != "succeeded" or job.report is None:
        return f":warning: Investigation `{job.job_id[:8]}` failed: {job.error}"
    r = job.report
    lines = [f"*Investigation* `{r.investigation_id[:8]}` — {r.status}, severity *{r.severity.value}*",
             r.summary[:600], "", "*Observations*"]
    lines += [f"• {o.claim[:200]} _({', '.join(o.evidence_ids)})_" for o in r.observations[:6]]
    if r.potential_causes:
        lines += ["", "*Hypotheses*"]
        lines += [f"• [{c.confidence}] {c.hypothesis[:200]}" for c in r.potential_causes[:4]]
    if r.runbooks:
        lines += ["", "*Runbooks*"] + [f"• `{c.source}` § {c.section}" for c in r.runbooks[:4]]
    if r.missing_information:
        lines += ["", "*Missing information*"] + [f"• {m[:200]}" for m in r.missing_information[:4]]
    lines += ["", f"_Generated by {r.generated_by.provider}"
                  f"{' (' + r.generated_by.model + ')' if r.generated_by.model else ''}. "
                  "Full report: GET /api/ops/investigations/" + r.investigation_id + "_"]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Router                                                                       #
# --------------------------------------------------------------------------- #

def create_slack_router(
    settings: Settings,
    services: OpsServices,
    runbooks: RunbookIndex,
    jobs: InvestigationJobs,
    provider_status: Callable[[], dict[str, Any]],
    *,
    post: PostFn = default_post,
) -> APIRouter:
    router = APIRouter()
    slack = settings.slack
    seen = _Seen()
    verifier = None
    if slack.enabled:
        from slack_sdk.signature import SignatureVerifier

        verifier = SignatureVerifier(slack.signing_secret)

    def safe_post(url: str, text: str) -> None:
        try:
            post(url, _ephemeral(text))
        except Exception:  # noqa: BLE001 - Slack delivery is best effort
            logger.warning("Slack response delivery failed", exc_info=True)

    def run(command: str, arg: str, response_url: str) -> None:
        try:
            if command == "health":
                text = format_health(services)
            elif command == "incidents":
                text = format_incidents(services)
            elif command == "runbook":
                text = format_runbooks(runbooks, arg)
            else:
                return
        except DataSourceError as exc:
            text = f":warning: {exc.source} unavailable: {exc.message}"
        except ValueError as exc:
            text = f":warning: {exc}"
        safe_post(response_url, text)

    def start_investigation(incident_id: str, response_url: str) -> None:
        status = provider_status()
        if not status["enabled"]:
            safe_post(response_url, f":warning: Investigations unavailable: {status['reason']}")
            return
        try:
            incident = services.incidents.get(incident_id, 60)
        except DataSourceError as exc:
            safe_post(response_url, f":warning: cannot resolve incident: {exc.message}")
            return
        if incident is None:
            safe_post(response_url, f"`{incident_id}` is not an active incident candidate. "
                                    "Try `/ops incidents`.")
            return
        # A fast job can finish before the "started" message is sent; the result
        # waits for it so the channel always reads start -> result.
        announced = threading.Event()

        def deliver(job: InvestigationJob) -> None:
            announced.wait(timeout=10)
            safe_post(response_url, format_report(job))

        try:
            job = jobs.submit(InvestigationRequest(incident_id=incident_id), incident, on_done=deliver)
        except InvestigationQueueFull as exc:
            safe_post(response_url, f":warning: {exc}")
            return
        safe_post(response_url, f":mag: Investigation `{job.job_id[:8]}` started for "
                                f"`{incident_id}`; results will follow here.")
        announced.set()

    @router.post("/slack/commands", include_in_schema=False)
    async def commands(request: Request, background: BackgroundTasks) -> JSONResponse:
        if verifier is None:
            return JSONResponse(status_code=404, content={"error": {
                "code": "slack_disabled", "message": "Slack integration is not configured"}})
        body = await request.body()
        if len(body) > 8_192:
            return JSONResponse(status_code=413, content={"error": {
                "code": "too_large", "message": "request body too large"}})
        if not verifier.is_valid(
            body=body,
            timestamp=request.headers.get("x-slack-request-timestamp", ""),
            signature=request.headers.get("x-slack-signature", ""),
        ):
            return JSONResponse(status_code=401, content={"error": {
                "code": "invalid_signature", "message": "invalid or stale Slack signature"}})

        form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", errors="replace")).items()}
        dedupe_key = form.get("trigger_id") or hashlib.sha256(body).hexdigest()
        if request.headers.get("x-slack-retry-num") or not seen.add(dedupe_key):
            return JSONResponse(content=_ephemeral("Already processing this request."))

        text = form.get("text", "").strip()
        command, _, arg = text.partition(" ")
        command, arg = command.lower(), arg.strip()
        user, channel = form.get("user_id", ""), form.get("channel_id", "")
        response_url = form.get("response_url", "")

        if command in {"", "help"}:
            return JSONResponse(content=_ephemeral(HELP))
        if command not in {"health", "incidents", "investigate", "runbook"}:
            return JSONResponse(content=_ephemeral(f"Unknown command `{command[:40]}`.\n\n{HELP}"))
        if not is_slack_response_url(response_url):
            return JSONResponse(status_code=400, content={"error": {
                "code": "invalid_response_url", "message": "response_url must be on hooks.slack.com"}})
        if command in SENSITIVE_COMMANDS and (user not in slack.allowed_user_ids or (
                slack.allowed_channel_ids and channel not in slack.allowed_channel_ids)):
            logger.info("Slack command denied", extra={"command": command, "user": user})
            return JSONResponse(content=_ephemeral(
                f"You are not authorised to run `/ops {command}` "
                "(ask an admin to add you to SLACK_ALLOWED_USER_IDS)."))
        if command == "runbook" and not arg:
            return JSONResponse(content=_ephemeral("Usage: `/ops runbook <query>`"))
        if command == "investigate":
            if not arg:
                return JSONResponse(content=_ephemeral("Usage: `/ops investigate <incident_id>`"))
            try:
                validate_incident_id(arg)
            except ValueError as exc:
                return JSONResponse(content=_ephemeral(str(exc)))
            background.add_task(start_investigation, arg, response_url)
            return JSONResponse(content=_ephemeral(f"Starting investigation of `{arg}`…"))

        background.add_task(run, command, arg[:300], response_url)
        return JSONResponse(content=_ephemeral(f"Working on `/ops {command}`…"))

    return router
