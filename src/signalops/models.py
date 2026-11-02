"""Typed operational responses shared by the API, dashboard, agent and Slack.

The central rule: a measurement that could not be taken is never a number.
:class:`Metric` carries an explicit :class:`ValueState`, so "zero", "nothing to
measure yet", "source not reachable" and "query failed" stay distinguishable all
the way to the screen.
"""

from __future__ import annotations

import datetime as dt
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)


class Status(str, Enum):
    """Component / overall health. Ordered by severity, see :data:`STATUS_RANK`."""

    healthy = "healthy"
    degraded = "degraded"  # working, but a signal is outside policy (stale, backlog)
    unhealthy = "unhealthy"  # reachable and failing (query terminated, ledger mismatch)
    unavailable = "unavailable"  # cannot be reached at all
    unknown = "unknown"  # no signal to judge by (not deployed, no telemetry yet)


STATUS_RANK = {
    Status.healthy: 0,
    Status.degraded: 1,
    Status.unhealthy: 2,
    Status.unavailable: 3,
}


class ValueState(str, Enum):
    ok = "ok"  # value is a real measurement (0 included)
    unknown = "unknown"  # the source answered but holds nothing to compute from
    unavailable = "unavailable"  # the source is not reachable or not deployed
    error = "error"  # the source was reached and the query failed


class Metric(BaseModel):
    name: str
    value: float | None = None
    state: ValueState
    unit: str | None = None
    window_minutes: int | None = None
    as_of: dt.datetime | None = None
    source: str
    detail: str | None = None

    @classmethod
    def ok(cls, name: str, value: float, *, source: str, unit: str | None = None,
           window_minutes: int | None = None, as_of: dt.datetime | None = None,
           detail: str | None = None) -> Metric:
        return cls(name=name, value=value, state=ValueState.ok, unit=unit, source=source,
                   window_minutes=window_minutes, as_of=as_of or utcnow(), detail=detail)

    @classmethod
    def missing(cls, name: str, state: ValueState, *, source: str, detail: str,
                unit: str | None = None, window_minutes: int | None = None) -> Metric:
        if state is ValueState.ok:
            raise ValueError("a missing metric cannot have state 'ok'")
        return cls(name=name, value=None, state=state, unit=unit, source=source,
                   window_minutes=window_minutes, as_of=utcnow(), detail=detail)


class TimePoint(BaseModel):
    bucket: dt.datetime
    value: float


class Series(BaseModel):
    name: str
    unit: str
    source: str
    state: ValueState
    points: list[TimePoint] = Field(default_factory=list)
    detail: str | None = None


# --------------------------------------------------------------------------- #
# Health                                                                       #
# --------------------------------------------------------------------------- #

class ComponentHealth(BaseModel):
    name: str
    status: Status
    checked_at: dt.datetime
    detail: str
    latency_ms: float | None = None
    observations: dict[str, Any] = Field(default_factory=dict)


class PipelineHealth(BaseModel):
    status: Status
    checked_at: dt.datetime
    components: list[ComponentHealth]
    summary: str


# --------------------------------------------------------------------------- #
# Metrics                                                                      #
# --------------------------------------------------------------------------- #

class StreamQueryState(BaseModel):
    query_name: str
    status: str  # active | idle | terminated | missing
    last_event_at: dt.datetime | None = None
    last_progress_at: dt.datetime | None = None
    last_batch_id: int | None = None
    seconds_since_event: float | None = None
    stale: bool | None = None
    exception: str | None = None


class PipelineMetrics(BaseModel):
    generated_at: dt.datetime
    window_minutes: int
    bucket_minutes: int
    metrics: list[Metric]
    series: list[Series]
    stream_queries: list[StreamQueryState]
    notes: list[str] = Field(default_factory=list)

    def metric(self, name: str) -> Metric | None:
        return next((m for m in self.metrics if m.name == name), None)


# --------------------------------------------------------------------------- #
# Dead letters                                                                 #
# --------------------------------------------------------------------------- #

class DlqRecord(BaseModel):
    partition: int
    offset: int
    timestamp: dt.datetime | None
    error: str | None
    source_partition: int | None = None
    source_offset: int | None = None
    rejected_at: str | None = None
    payload_preview: str | None = None


class NormalizeFailure(BaseModel):
    raw_id: int
    landed_at: dt.datetime
    error: str
    host_name: str | None = None


class DlqSummary(BaseModel):
    generated_at: dt.datetime
    topic: str
    window_minutes: int
    retained_records: Metric
    records_in_window: Metric
    raw_records_in_window: Metric
    dlq_ratio: Metric
    sample_size: int
    sample_error_counts: dict[str, int]
    sample_covers_window: bool | None
    samples: list[DlqRecord]
    normalize_failures_in_window: Metric
    recent_normalize_failures: list[NormalizeFailure]
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Detections and timelines                                                     #
# --------------------------------------------------------------------------- #

class Detection(BaseModel):
    detection_id: int
    host_name: str
    window_start: dt.datetime
    window_end: dt.datetime
    scored_at: dt.datetime
    score: float
    flagged: bool
    signals: dict[str, float]
    model_version: str | None
    event_count: int


class DetectionPage(BaseModel):
    generated_at: dt.datetime
    window_minutes: int
    flagged_only: bool
    limit: int
    offset: int
    total: int
    items: list[Detection]
    score_semantics: str = (
        "score = largest decision signal / its calibrated threshold; >= 1.0 means flagged. "
        "It is a ratio to a cut, not a probability."
    )


class TimelineEvent(BaseModel):
    event_id: str
    occurred_at: dt.datetime
    category: str
    action: str | None = None
    outcome: str | None = None
    severity: int | None = None
    message: str | None = None
    user_name: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None


class DetectionDetail(BaseModel):
    detection: Detection
    thresholds: dict[str, float] | None
    events: list[TimelineEvent]
    events_requested: int
    events_found: int
    note: str | None = None


class HostTimeline(BaseModel):
    host_name: str
    known_host: bool
    window_start: dt.datetime
    window_end: dt.datetime
    events: list[TimelineEvent]
    events_truncated: bool
    detections: list[Detection]


# --------------------------------------------------------------------------- #
# Ledger                                                                       #
# --------------------------------------------------------------------------- #

class LedgerFinding(BaseModel):
    kind: str
    detail: str
    event_id: str | None = None
    sequence_number: int | None = None


class LedgerVerification(BaseModel):
    verification_id: int
    started_at: dt.datetime
    finished_at: dt.datetime
    intact: bool
    events_checked: int
    blocks_checked: int
    unsealed_events: int
    finding_count: int
    findings: list[LedgerFinding]


class LedgerStatus(BaseModel):
    generated_at: dt.datetime
    status: Status
    detail: str
    blocks: int | None = None
    digested_events: int | None = None
    unsealed_events: int | None = None
    head_sequence: int | None = None
    head_hash: str | None = None
    last_sealed_at: dt.datetime | None = None
    seconds_since_seal: float | None = None
    last_verification: LedgerVerification | None = None
    recent_failures: list[LedgerVerification] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Incident candidates                                                          #
# --------------------------------------------------------------------------- #

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    unknown = "unknown"


class IncidentCandidate(BaseModel):
    """A deterministic rule match. Never a confirmed incident."""

    incident_id: str
    rule: str
    title: str
    severity: Severity
    severity_reason: str
    scope: str
    status: str = "candidate"
    detected_at: dt.datetime
    window_minutes: int
    facts: list[Metric]
    runbook_query: str
    related_tools: list[str]


class IncidentList(BaseModel):
    generated_at: dt.datetime
    window_minutes: int
    candidates: list[IncidentCandidate]
    rules_skipped: list[str] = Field(default_factory=list)
    policy: str = (
        "Candidates are derived from fixed rules over observed signals (see docs/signalops.md). "
        "They are not confirmed incidents; severity follows the documented rule policy."
    )
