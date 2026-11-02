"""Deterministic incident candidates.

The pipeline has no incident entity, and inventing an incident-management system
is out of scope. Instead a fixed set of rules runs over the observed signals and
each match becomes an :class:`IncidentCandidate`:

====================== =========================================== ==========================
rule                   fires when (window W)                       severity
====================== =========================================== ==========================
stream_query_failed    a Spark query terminated with an exception  critical
ledger_integrity       latest verification found findings          critical
stream_stalled         a query has no listener event > threshold   high
dlq_spike              DLQ >= min records and ratio >= warn        high if ratio >= high,
                                                                   else medium
normalize_failures     normalisation errors in W                   medium
ledger_seal_stalled    unsealed events and no seal > threshold     medium
anomaly_cluster        flagged detection windows for a host in W   high if >= cluster_high,
                                                                   medium if >= 2, else low
normalize_backlog      pending rows or oldest-pending age > limit  low
====================== =========================================== ==========================

IDs are ``<rule>:<scope>`` — stable while the condition holds, so a dashboard
selection or a Slack ``/ops investigate`` keeps pointing at the same thing. A
rule whose inputs could not be read is reported in ``rules_skipped`` rather
than silently treated as "no incident".
"""

from __future__ import annotations

import contextlib
import re
from typing import Any

from signalops.config import Settings
from signalops.models import (
    IncidentCandidate,
    IncidentList,
    Metric,
    Severity,
    ValueState,
    utcnow,
)
from signalops.services.common import clamp_window, seconds_since
from signalops.services.dlq import DlqService
from signalops.services.ledger import LedgerService
from signalops.services.metrics import PENDING_SQL, MetricsService
from signalops.sources.errors import DataSourceError
from signalops.sources.postgres import Database

INCIDENT_ID_PATTERN = re.compile(r"^[a-z_]{3,40}:[A-Za-z0-9._-]{1,253}$")

SEVERITY_ORDER = {Severity.critical: 0, Severity.high: 1, Severity.medium: 2,
                  Severity.low: 3, Severity.unknown: 4}

ANOMALY_CLUSTER_SQL = """
SELECT host_name, count(*) AS windows, max(score) AS max_score,
       min(window_start) AS first_window, max(window_end) AS last_window
  FROM analytics.detections
 WHERE flagged AND window_start >= now() - make_interval(mins => %(window)s)
 GROUP BY host_name
 ORDER BY windows DESC, max_score DESC
 LIMIT 20
"""

NORMALIZE_FAILURE_REASONS_SQL = """
SELECT left(normalize_error, 120) AS reason, count(*) AS n
  FROM evidence.raw_events
 WHERE normalize_error IS NOT NULL
   AND landed_at >= now() - make_interval(mins => %(window)s)
 GROUP BY 1 ORDER BY 2 DESC LIMIT 5
"""


def validate_incident_id(incident_id: str) -> str:
    if not INCIDENT_ID_PATTERN.fullmatch(incident_id or ""):
        raise ValueError("incident_id must look like '<rule>:<scope>', e.g. 'dlq_spike:logs.raw.dlq'")
    return incident_id


class IncidentService:
    def __init__(self, db: Database, settings: Settings, metrics: MetricsService,
                 dlq: DlqService, ledger: LedgerService) -> None:
        self._db = db
        self._settings = settings
        self._t = settings.thresholds
        self._metrics = metrics
        self._dlq = dlq
        self._ledger = ledger

    def candidates(self, window_minutes: int = 60) -> IncidentList:
        window = clamp_window(window_minutes)
        now = utcnow()
        found: list[IncidentCandidate] = []
        skipped: list[str] = []

        def candidate(rule: str, scope: str, title: str, severity: Severity, reason: str,
                      facts: list[Metric], runbook_query: str, tools: list[str]) -> None:
            found.append(IncidentCandidate(
                incident_id=f"{rule}:{scope}", rule=rule, title=title, severity=severity,
                severity_reason=reason, scope=scope, detected_at=now, window_minutes=window,
                facts=facts, runbook_query=runbook_query, related_tools=tools))

        # -- Spark ---------------------------------------------------------------
        try:
            for q in self._metrics.stream_queries(now):
                if q.status == "terminated" and q.exception:
                    candidate(
                        "stream_query_failed", q.query_name,
                        f"Spark query {q.query_name} terminated with an exception",
                        Severity.critical, "rule policy: a terminated query stops one pipeline output",
                        [Metric.ok("spark.query.seconds_since_event", q.seconds_since_event or 0,
                                   source="ops.stream_queries", unit="seconds",
                                   detail=f"exception: {(q.exception or '')[:300]}")],
                        "spark streaming query terminated exception checkpoint",
                        ["get_pipeline_health", "get_pipeline_metrics", "get_recent_failures"])
                elif q.stale:
                    candidate(
                        "stream_stalled", q.query_name, f"Spark query {q.query_name} has gone quiet",
                        Severity.high,
                        f"rule policy: no listener event for more than {self._t.stream_stale_seconds}s",
                        [Metric.ok("spark.query.seconds_since_event", q.seconds_since_event or 0,
                                   source="ops.stream_queries", unit="seconds")],
                        "spark processing delay stalled micro-batch lag",
                        ["get_pipeline_health", "get_pipeline_metrics"])
        except DataSourceError as exc:
            skipped.append(f"stream_query_failed/stream_stalled: {exc.message}")

        # -- Dead letters -------------------------------------------------------
        summary = self._dlq.summary(window_minutes=window, sample_per_partition=50)
        dlq_count, ratio = summary.records_in_window, summary.dlq_ratio
        if dlq_count.state is not ValueState.ok:
            skipped.append(f"dlq_spike: {dlq_count.detail}")
        elif (dlq_count.value or 0) >= self._t.dlq_min_records:
            reason_facts = [
                Metric.ok(f"dlq.sample.reason.{reason}", n, source=f"kafka tail sample ({summary.topic})",
                          unit="records", window_minutes=window,
                          detail=None if summary.sample_covers_window else "from a partial sample")
                for reason, n in list(summary.sample_error_counts.items())[:5]
            ]
            facts = [dlq_count, summary.raw_records_in_window, ratio, *reason_facts]
            if ratio.state is ValueState.ok and (ratio.value or 0) >= self._t.dlq_ratio_warn:
                high = (ratio.value or 0) >= self._t.dlq_ratio_high
                candidate(
                    "dlq_spike", summary.topic,
                    f"{int(dlq_count.value or 0)} records dead-lettered "
                    f"({(ratio.value or 0):.1%} of raw input)",
                    Severity.high if high else Severity.medium,
                    f"rule policy: DLQ ratio {(ratio.value or 0):.1%} "
                    f"{'>=' if high else '<'} {self._t.dlq_ratio_high:.0%} high threshold",
                    facts, "dead letter queue validation errors schema " + " ".join(
                        summary.sample_error_counts)[:200],
                    ["get_dlq_summary", "get_pipeline_metrics", "search_runbooks"])
            elif ratio.state is not ValueState.ok:
                candidate(
                    "dlq_spike", summary.topic,
                    f"{int(dlq_count.value or 0)} records dead-lettered (ratio unavailable)",
                    Severity.medium, f"rule policy: ratio could not be computed ({ratio.detail})",
                    facts, "dead letter queue validation errors",
                    ["get_dlq_summary", "get_pipeline_metrics", "search_runbooks"])

        # -- Normalisation ------------------------------------------------------
        failures = summary.normalize_failures_in_window
        if failures.state is not ValueState.ok:
            skipped.append(f"normalize_failures: {failures.detail}")
        elif failures.value:
            facts = [failures]
            with contextlib.suppress(DataSourceError):
                facts += [Metric.ok("normalize.reason", r["n"], source="evidence.raw_events",
                                    unit="records", window_minutes=window, detail=r["reason"])
                          for r in self._db.fetch_all(NORMALIZE_FAILURE_REASONS_SQL, {"window": window})]
            candidate("normalize_failures", "evidence.raw_events",
                      f"{int(failures.value)} landed rows failed normalisation",
                      Severity.medium, "rule policy: any normalisation failure needs a look",
                      facts, "schema validation normalization error raw_events",
                      ["get_dlq_summary", "get_recent_failures", "search_runbooks"])

        try:
            row: dict[str, Any] = self._db.fetch_one(PENDING_SQL) or {}
            pending = int(row.get("pending") or 0)
            age = seconds_since(row.get("oldest"), now)
            if pending > self._t.normalize_backlog_rows or (
                    age is not None and age > self._t.normalize_backlog_age_seconds):
                candidate("normalize_backlog", "evidence.raw_events",
                          f"{pending} landed rows waiting for normalisation",
                          Severity.low,
                          "rule policy: backlog above row/age threshold (is the sealer running?)",
                          [Metric.ok("postgres.normalize_pending", pending, source="evidence.raw_events",
                                     unit="records"),
                           Metric.ok("postgres.normalize_oldest_pending_age", age or 0,
                                     source="evidence.raw_events", unit="seconds")],
                          "normalization backlog sealer raw_events pending",
                          ["get_pipeline_metrics", "get_ledger_status"])
        except DataSourceError as exc:
            skipped.append(f"normalize_backlog: {exc.message}")

        # -- Ledger -------------------------------------------------------------
        ledger = self._ledger.status()
        last = ledger.last_verification
        if last is not None and not last.intact:
            candidate("ledger_integrity", "ledger",
                      f"Ledger verification found {last.finding_count} integrity finding(s)",
                      Severity.critical, "rule policy: evidence integrity failures are always critical",
                      [Metric.ok("ledger.finding_count", last.finding_count,
                                 source="ops.ledger_verifications",
                                 detail=", ".join(sorted({f.kind for f in last.findings})))],
                      "evidence ledger verification failure tamper digest mismatch",
                      ["get_ledger_status", "search_runbooks"])
        if (ledger.unsealed_events or 0) > 0 and (
                ledger.seconds_since_seal is None
                or ledger.seconds_since_seal > self._t.seal_stale_seconds):
            candidate("ledger_seal_stalled", "ledger",
                      f"{ledger.unsealed_events} events unsealed with no recent seal",
                      Severity.medium,
                      f"rule policy: no seal for more than {self._t.seal_stale_seconds}s widens the "
                      "undetectable-edit window",
                      [Metric.ok("ledger.unsealed_events", ledger.unsealed_events or 0,
                                 source="ledger.chain_status", unit="events")],
                      "evidence ledger sealing unsealed backlog sealer",
                      ["get_ledger_status", "get_pipeline_health"])

        # -- Detections ---------------------------------------------------------
        try:
            for r in self._db.fetch_all(ANOMALY_CLUSTER_SQL, {"window": window}):
                n = int(r["windows"])
                severity = (Severity.high if n >= self._t.anomaly_cluster_high
                            else Severity.medium if n >= 2 else Severity.low)
                candidate("anomaly_cluster", r["host_name"],
                          f"{n} flagged detection window(s) on {r['host_name']}",
                          severity, f"rule policy: {n} flagged windows "
                                    f"(high at >= {self._t.anomaly_cluster_high})",
                          [Metric.ok("detections.flagged_windows", n, source="analytics.detections",
                                     unit="windows", window_minutes=window),
                           Metric.ok("detections.max_score", float(r["max_score"]),
                                     source="analytics.detections",
                                     detail="ratio to calibrated threshold, not a probability")],
                          "anomaly detection investigation host suspicious activity",
                          ["get_detection_details", "get_host_timeline", "search_runbooks"])
        except DataSourceError as exc:
            skipped.append(f"anomaly_cluster: {exc.message}")

        found.sort(key=lambda c: (SEVERITY_ORDER[c.severity], c.incident_id))
        return IncidentList(generated_at=now, window_minutes=window, candidates=found,
                            rules_skipped=skipped)

    def get(self, incident_id: str, window_minutes: int = 60) -> IncidentCandidate | None:
        validate_incident_id(incident_id)
        return next((c for c in self.candidates(window_minutes).candidates
                     if c.incident_id == incident_id), None)
