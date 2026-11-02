"""Fixtures: a healthy pipeline described entirely through fakes.

Individual tests break one thing at a time (a query failure, a DLQ burst, a
broker outage) and assert on how the operational layer reports it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from signalops.config import REPO_ROOT, Settings
from signalops.retrieval.runbooks import RunbookIndex
from signalops.services import OpsServices
from signalops.services import detections as det_sql
from signalops.services import dlq as dlq_sql
from signalops.services import health as health_sql
from signalops.services import incidents as inc_sql
from signalops.services import ledger as ledger_sql
from signalops.services import metrics as m
from tests.signalops.fakes import FakeDatabase, FakeKafka, ago

QUERIES = ("normalized-events", "dead-letters", "host-activity-features",
           "peer-connection-features", "evidence-store")


def healthy_db() -> FakeDatabase:
    db = FakeDatabase()
    db.on(m.LANDED_IN_WINDOW_SQL, {"n": 1500})
    db.on(m.PENDING_SQL, {"pending": 0, "oldest": None})
    db.on(m.NORMALIZE_FAILURES_SQL, {"n": 0})
    db.on(m.LANDING_LATENCY_SQL, {"n": 1500, "p50": 6.2, "p95": 11.8})
    db.on(m.NORMALIZE_LATENCY_SQL, {"n": 1500, "p50": 14.0, "p95": 29.0})
    db.on(m.LANDED_SERIES_SQL, [{"bucket": ago(minutes=5).replace(second=0, microsecond=0),
                                 "landed": 750, "failed": 0}])
    db.on(m.STREAM_QUERIES_SQL, [
        {"query_name": q, "status": "active", "last_event_at": ago(seconds=10),
         "last_progress_at": ago(seconds=10), "last_batch_id": 42, "exception": None}
        for q in QUERIES])
    db.on(m.STREAM_WINDOW_SQL, [
        {"query_name": "normalized-events", "batches": 6, "input_rows": 1500, "output_rows": 1500,
         "batches_reporting_output": 6, "last_batch": ago(seconds=10)},
        {"query_name": "dead-letters", "batches": 6, "input_rows": 1500, "output_rows": 0,
         "batches_reporting_output": 6, "last_batch": ago(seconds=10)},
    ])
    db.on(m.STREAM_LATEST_SQL, [
        {"query_name": "normalized-events", "batch_timestamp": ago(seconds=10),
         "processed_rows_per_second": 150.0, "max_offsets_behind_latest": 0, "trigger_execution_ms": 900},
    ])
    db.on(m.STREAM_SERIES_SQL, [])
    db.on(m.DETECTION_WINDOW_SQL, {"scored": 120, "flagged": 0, "last_scored": ago(seconds=20)})
    db.on(m.DETECTION_SERIES_SQL, [])
    db.on(dlq_sql.NORMALIZE_FAILURE_COUNT_SQL, {"n": 0})
    db.on(dlq_sql.RECENT_NORMALIZE_FAILURES_SQL, [])
    db.on(ledger_sql.CHAIN_STATUS_SQL, {
        "blocks": 10, "digested_events": 5000, "unsealed_events": 40, "head_sequence": 9,
        "head_hash": "ab" * 32, "last_sealed_at": ago(seconds=20)})
    db.on(ledger_sql.VERIFICATIONS_SQL, {
        "verification_id": 3, "started_at": ago(minutes=5, seconds=3), "finished_at": ago(minutes=5),
        "intact": True, "events_checked": 4960, "blocks_checked": 10, "unsealed_events": 40,
        "finding_count": 0, "findings": []})
    db.on(ledger_sql.RECENT_FAILURES_SQL, [])
    db.on(health_sql.DETECTOR_SQL, {"runs": 1, "last_scored": ago(seconds=20)})
    db.on(inc_sql.ANOMALY_CLUSTER_SQL, [])
    db.on(inc_sql.NORMALIZE_FAILURE_REASONS_SQL, [])
    db.on(det_sql.LIST_SQL, [])
    db.on(det_sql.COUNT_SQL, {"n": 0})
    return db


def healthy_kafka() -> FakeKafka:
    kafka = FakeKafka()
    kafka.topic_partitions = dict.fromkeys(("logs.raw", "logs.normalized", "logs.raw.dlq", "features.host_activity", "features.peer_connections", "alerts.anomalies"), 2)
    kafka.marks = {"logs.raw": {0: (0, 10_000), 1: (0, 10_000)}, "logs.raw.dlq": {0: (0, 0), 1: (0, 0)}}
    kafka.since = {"logs.raw": {0: 9_250, 1: 9_250}, "logs.raw.dlq": {0: -1, 1: -1}}
    return kafka


def make_settings(**overrides: object) -> Settings:
    base = {"cache_ttl_seconds": 0.0, "runbook_dir": REPO_ROOT / "runbooks"}
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.fixture
def db() -> FakeDatabase:
    return healthy_db()


@pytest.fixture
def kafka() -> FakeKafka:
    return healthy_kafka()


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def services(db: FakeDatabase, kafka: FakeKafka, settings: Settings) -> OpsServices:
    return OpsServices.build(settings, db=db, kafka=kafka)


@pytest.fixture
def runbooks() -> RunbookIndex:
    return RunbookIndex.load(Path(REPO_ROOT / "runbooks"))


def inject_dlq_burst(kafka: FakeKafka, *, count: int = 300, reasons: tuple[str, ...] = (
        "unknown_category", "severity_out_of_range")) -> None:
    """Simulate a validation incident: `count` DLQ records in the window."""
    from tests.signalops.fakes import dlq_record

    kafka.marks["logs.raw.dlq"] = {0: (0, count), 1: (0, 0)}
    kafka.since["logs.raw.dlq"] = {0: 0, 1: -1}
    kafka.records["logs.raw.dlq"] = [
        dlq_record(i, reasons[i % len(reasons)],
                   payload=f'{{"event_id":"e{i}","category":"weird","labels":{{"ground_truth":'
                           '{"is_anomaly":true,"scenario":"reverse_shell"}}}')
        for i in range(min(count, 50))]
