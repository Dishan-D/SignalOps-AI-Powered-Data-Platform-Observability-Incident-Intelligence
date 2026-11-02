"""Deterministic component health.

No LLM, no Slack, no network call beyond the pipeline's own infrastructure.
Checks run concurrently with per-source timeouts, so the endpoint's worst case
is bounded by the slowest single check rather than their sum.

Policy (documented in docs/signalops.md):

* overall = worst status among components that could be judged; ``unknown``
  components are listed but do not by themselves make the pipeline unhealthy.
* every non-healthy component carries a one-line reason.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from signalops.config import Settings
from signalops.models import (
    STATUS_RANK,
    ComponentHealth,
    PipelineHealth,
    Status,
    utcnow,
)
from signalops.services.common import seconds_since
from signalops.services.ledger import LedgerService
from signalops.services.metrics import MetricsService
from signalops.sources.errors import DataSourceError
from signalops.sources.kafka import KafkaInspector
from signalops.sources.postgres import Database

DETECTOR_SQL = """
SELECT (SELECT count(*) FROM analytics.model_runs) AS runs,
       (SELECT max(scored_at) FROM analytics.detections
         WHERE window_start >= now() - interval '1 day') AS last_scored
"""

#: Queries that only exist when optional sinks are enabled.
OPTIONAL_QUERIES = frozenset({"evidence-store"})


def overall_status(components: list[ComponentHealth]) -> Status:
    known = [c.status for c in components if c.status is not Status.unknown]
    if not known:
        return Status.unknown
    return max(known, key=lambda s: STATUS_RANK[s])


class HealthService:
    def __init__(self, db: Database, kafka: KafkaInspector | None, settings: Settings,
                 metrics: MetricsService, ledger: LedgerService) -> None:
        self._db = db
        self._kafka = kafka
        self._settings = settings
        self._metrics = metrics
        self._ledger = ledger
        self._pool = ThreadPoolExecutor(max_workers=5, thread_name_prefix="health")

    def check(self) -> PipelineHealth:
        checks: list[tuple[str, Callable[[], ComponentHealth]]] = [
            ("postgres", self.postgres),
            ("kafka", self.kafka),
            ("spark", self.spark),
            ("detector", self.detector),
            ("ledger", self.ledger),
        ]
        futures = [(name, self._pool.submit(self._timed, name, fn)) for name, fn in checks]
        budget = self._settings.kafka_timeout_seconds + self._settings.db_connect_timeout_seconds + 4
        components = []
        for name, future in futures:
            try:
                components.append(future.result(timeout=budget))
            except Exception as exc:  # noqa: BLE001 - a check must never fail the endpoint
                components.append(ComponentHealth(
                    name=name, status=Status.unknown, checked_at=utcnow(),
                    detail=f"health check did not complete: {exc.__class__.__name__}"))
        status = overall_status(components)
        bad = [f"{c.name}: {c.status.value}" for c in components if c.status is not Status.healthy]
        summary = "all components healthy" if not bad else "; ".join(bad)
        return PipelineHealth(status=status, checked_at=utcnow(), components=components,
                              summary=summary)

    @staticmethod
    def _timed(name: str, fn: Callable[[], ComponentHealth]) -> ComponentHealth:
        started = time.perf_counter()
        try:
            result = fn()
        except DataSourceError as exc:
            result = ComponentHealth(
                name=name, status=Status.unavailable if exc.unavailable else Status.unknown,
                checked_at=utcnow(), detail=exc.message)
        result.latency_ms = round((time.perf_counter() - started) * 1000, 1)
        return result

    # -- components ------------------------------------------------------------

    def postgres(self) -> ComponentHealth:
        try:
            self._db.ping()
        except DataSourceError as exc:
            return ComponentHealth(
                name="postgres", checked_at=utcnow(), detail=exc.message,
                status=Status.unavailable if exc.unavailable else Status.unhealthy)
        return ComponentHealth(name="postgres", status=Status.healthy, checked_at=utcnow(),
                               detail="accepting read-only queries")

    def kafka(self) -> ComponentHealth:
        if self._kafka is None:
            return ComponentHealth(name="kafka", status=Status.unknown, checked_at=utcnow(),
                                   detail="Kafka inspection not configured")
        topics = self._kafka.topics()
        missing = [t for t in self._settings.topics if t not in topics]
        observations = {"topics": {t: topics[t] for t in self._settings.topics if t in topics}}
        if missing:
            return ComponentHealth(name="kafka", status=Status.degraded, checked_at=utcnow(),
                                   detail=f"broker reachable; missing topics: {', '.join(missing)}",
                                   observations=observations)
        return ComponentHealth(name="kafka", status=Status.healthy, checked_at=utcnow(),
                               detail=f"broker reachable; {len(self._settings.topics)} pipeline topics present",
                               observations=observations)

    def spark(self) -> ComponentHealth:
        now = utcnow()
        try:
            queries = self._metrics.stream_queries(now)
        except DataSourceError as exc:
            return ComponentHealth(
                name="spark", status=Status.unknown, checked_at=now,
                detail=f"stream telemetry unreadable: {exc.message}")
        seen = [q for q in queries if q.status != "missing"]
        observations = {q.query_name: {"status": q.status,
                                       "seconds_since_event": q.seconds_since_event}
                        for q in queries}
        if not seen:
            return ComponentHealth(
                name="spark", status=Status.unknown, checked_at=now, observations=observations,
                detail="no stream telemetry recorded (job not started, or SPARK_PROGRESS_DSN unset)")

        failed = [q for q in seen if q.status == "terminated" and q.exception]
        stopped = [q for q in seen if q.status == "terminated" and not q.exception]
        stale = [q for q in seen if q.stale]
        absent = [q for q in queries if q.status == "missing" and q.query_name not in OPTIONAL_QUERIES]
        if failed:
            first = failed[0]
            return ComponentHealth(
                name="spark", status=Status.unhealthy, checked_at=now, observations=observations,
                detail=f"query {first.query_name!r} terminated with an exception: "
                       f"{(first.exception or '')[:200]}")
        problems = []
        if stopped:
            problems.append("stopped: " + ", ".join(q.query_name for q in stopped))
        if stale:
            problems.append("no listener event for >"
                            f"{self._settings.thresholds.stream_stale_seconds}s: "
                            + ", ".join(q.query_name for q in stale))
        if absent:
            problems.append("never reported: " + ", ".join(q.query_name for q in absent))
        if problems:
            return ComponentHealth(name="spark", status=Status.degraded, checked_at=now,
                                   detail="; ".join(problems), observations=observations)
        return ComponentHealth(name="spark", status=Status.healthy, checked_at=now,
                               observations=observations,
                               detail=f"{len(seen)} streaming queries reporting")

    def detector(self) -> ComponentHealth:
        now = utcnow()
        row = self._db.fetch_one(DETECTOR_SQL) or {}
        if not row.get("runs"):
            return ComponentHealth(name="detector", status=Status.unknown, checked_at=now,
                                   detail="no model run registered (scorer not deployed; "
                                          "`make train` then the `detect` profile)")
        age = seconds_since(row.get("last_scored"), now)
        observations = {"seconds_since_last_score": age}
        if age is None:
            return ComponentHealth(name="detector", status=Status.degraded, checked_at=now,
                                   observations=observations,
                                   detail="model registered but no window scored in the last day")
        if age > self._settings.thresholds.detector_stale_seconds:
            return ComponentHealth(name="detector", status=Status.degraded, checked_at=now,
                                   observations=observations,
                                   detail=f"last window scored {int(age)}s ago")
        return ComponentHealth(name="detector", status=Status.healthy, checked_at=now,
                               observations=observations,
                               detail=f"last window scored {int(age)}s ago")

    def ledger(self) -> ComponentHealth:
        status = self._ledger.status()
        return ComponentHealth(
            name="ledger", status=status.status, checked_at=status.generated_at,
            detail=status.detail,
            observations={"unsealed_events": status.unsealed_events,
                          "seconds_since_seal": status.seconds_since_seal,
                          "head_sequence": status.head_sequence},
        )


def is_ready(db: Database) -> tuple[bool, str]:
    """Readiness: can this API answer questions at all? (Postgres reachable.)"""
    try:
        db.ping()
    except DataSourceError as exc:
        return False, exc.message
    return True, "ok"


__all__ = ["HealthService", "is_ready", "overall_status"]
