"""Operational services: the single implementation of every operational query.

The API, the dashboard (through the API), the investigation tools and the Slack
commands all call these; none of them carries SQL of its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

from signalops.config import Settings
from signalops.models import (
    DlqSummary,
    IncidentList,
    LedgerStatus,
    PipelineHealth,
    PipelineMetrics,
)
from signalops.services.common import TTLCache
from signalops.services.detections import DetectionService
from signalops.services.dlq import DlqService
from signalops.services.health import HealthService
from signalops.services.incidents import IncidentService
from signalops.services.ledger import LedgerService
from signalops.services.metrics import MetricsService
from signalops.sources.kafka import ConfluentKafkaInspector, KafkaInspector
from signalops.sources.postgres import Database, PostgresDatabase

_DEFAULT = object()


@dataclass
class OpsServices:
    settings: Settings
    db: Database
    kafka: KafkaInspector | None
    metrics: MetricsService
    dlq: DlqService
    detections: DetectionService
    ledger: LedgerService
    health: HealthService
    incidents: IncidentService
    cache: TTLCache = field(default_factory=lambda: TTLCache(5.0))

    @classmethod
    def build(cls, settings: Settings, *, db: Database | None = None,
              kafka: KafkaInspector | None | object = _DEFAULT) -> OpsServices:
        db = db or PostgresDatabase(
            settings.postgres_dsn,
            connect_timeout_seconds=settings.db_connect_timeout_seconds,
            statement_timeout_ms=settings.db_statement_timeout_ms,
        )
        if kafka is _DEFAULT:
            kafka = (ConfluentKafkaInspector(settings.kafka_bootstrap_servers,
                                             timeout_seconds=settings.kafka_timeout_seconds)
                     if settings.kafka_bootstrap_servers else None)
        kafka = cast("KafkaInspector | None", kafka)
        metrics = MetricsService(db, kafka, settings)
        dlq = DlqService(db, kafka, settings)
        ledger = LedgerService(db, settings.thresholds)
        return cls(
            settings=settings, db=db, kafka=kafka, metrics=metrics, dlq=dlq,
            detections=DetectionService(db), ledger=ledger,
            health=HealthService(db, kafka, settings, metrics, ledger),
            incidents=IncidentService(db, settings, metrics, dlq, ledger),
            cache=TTLCache(settings.cache_ttl_seconds),
        )

    # Cached façades for the read paths that dashboards poll.

    def cached_health(self) -> PipelineHealth:
        return self.cache.get_or_compute("health", self.health.check)

    def cached_metrics(self, window_minutes: int) -> PipelineMetrics:
        return self.cache.get_or_compute(("metrics", window_minutes),
                                         lambda: self.metrics.collect(window_minutes))

    def cached_dlq(self, window_minutes: int, sample: int) -> DlqSummary:
        return self.cache.get_or_compute(("dlq", window_minutes, sample),
                                         lambda: self.dlq.summary(window_minutes, sample))

    def cached_ledger(self) -> LedgerStatus:
        return self.cache.get_or_compute("ledger", self.ledger.status)

    def cached_incidents(self, window_minutes: int) -> IncidentList:
        return self.cache.get_or_compute(("incidents", window_minutes),
                                         lambda: self.incidents.candidates(window_minutes))


__all__ = ["OpsServices"]
