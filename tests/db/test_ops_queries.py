"""SignalOps services against a real PostgreSQL (skipped when none is reachable).

The unit suite proves the services interpret results correctly; this proves
the SQL itself is valid against the migrated schema and returns what the
services expect — including the read-only session guarantee.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from forensics.ledger import verifier
from forensics.ledger.sealer import record_verification
from signalops.config import REPO_ROOT, Settings
from signalops.models import Status, ValueState
from signalops.services import OpsServices
from signalops.sources.errors import DataSourceError
from signalops.sources.postgres import PostgresDatabase
from tests.db.helpers import generate, land, normalize


@pytest.fixture
def ops(conn, migrated_db: str):
    with conn.cursor() as cur:
        cur.execute("TRUNCATE ops.stream_progress, ops.stream_queries, ops.ledger_verifications")
        cur.execute("TRUNCATE analytics.detections, analytics.model_runs RESTART IDENTITY CASCADE")
    database = PostgresDatabase(migrated_db)
    settings = Settings(postgres_dsn=migrated_db, cache_ttl_seconds=0, runbook_dir=REPO_ROOT / "runbooks")
    yield OpsServices.build(settings, db=database, kafka=None), conn
    database.close()


def _populate(conn) -> list:
    events = generate(400, host_count=4, user_count=5, anomaly_rate=0.05, seed=7)
    land(conn, events)
    normalize(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM ledger.seal_block(10000)")
        now = dt.datetime.now(tz=dt.timezone.utc)
        for i, name in enumerate(("normalized-events", "dead-letters")):
            cur.execute(
                """INSERT INTO ops.stream_queries (query_name, query_id, run_id, status, started_at,
                                                   last_event_at, last_progress_at, last_batch_id)
                   VALUES (%s, %s, 'run', 'active', %s, %s, %s, 3)""",
                (name, f"q{i}", now, now, now))
            cur.execute(
                """INSERT INTO ops.stream_progress (query_name, query_id, run_id, batch_id, batch_timestamp,
                       num_input_rows, processed_rows_per_second, max_offsets_behind_latest,
                       sink_output_rows, sources)
                   VALUES (%s, %s, %s, 3, %s, 400, 120.0, 5, %s, '[]')""",
                (name, f"q{i}", f"run-{i}", now, 400 if i == 0 else 7))
        cur.execute(
            """INSERT INTO analytics.model_runs (model_version, window_size, stride, vocabulary_size,
                   template_count, thresholds) VALUES ('test-v1', 16, 8, 50, 40, %s) RETURNING run_id""",
            (json.dumps({"max_nll": 5.0}),))
        run_id = cur.fetchone()[0]
        cur.execute("SELECT analytics.ensure_detection_partition(now()::date)")
        host = events[0].host.name
        ids = [e.event_id for e in events if e.host.name == host][:5]
        cur.execute(
            """INSERT INTO analytics.detections (run_id, host_name, window_start, window_end, signals,
                   score, flagged, event_ids) VALUES (%s, %s, now() - interval '5 minutes', now(), %s, 1.6,
                   true, %s::uuid[])""",
            (run_id, host, json.dumps({"max_nll": 8.0}), ids))
    record_verification(conn, verifier.verify(conn), started_at=dt.datetime.now(tz=dt.timezone.utc),
                        finished_at=dt.datetime.now(tz=dt.timezone.utc))
    return events


def test_metrics_against_real_schema(ops) -> None:
    services, conn = ops
    _populate(conn)
    metrics = services.metrics.collect(60)
    assert metrics.metric("postgres.raw_events.landed_in_window").value == 400
    assert metrics.metric("postgres.normalize_pending").value == 0
    assert metrics.metric("spark.raw_rows_processed").value == 400
    assert metrics.metric("spark.dlq_rows_written").value == 7
    assert metrics.metric("detections.flagged_windows").value == 1
    landing = metrics.metric("latency.landing.p50")
    assert landing.state in (ValueState.ok, ValueState.unknown)  # depends on generator timestamps
    assert all(s.state is not ValueState.error for s in metrics.series), [
        (s.name, s.detail) for s in metrics.series]


def test_health_ledger_and_incidents_against_real_schema(ops) -> None:
    services, conn = ops
    _populate(conn)
    ledger = services.ledger.status()
    assert ledger.status is Status.healthy, ledger.detail
    assert ledger.last_verification is not None and ledger.last_verification.intact
    components = {c.name: c for c in services.health.check().components}
    assert components["postgres"].status is Status.healthy
    assert components["detector"].status is Status.healthy
    candidates = services.incidents.candidates(60).candidates
    assert any(c.rule == "anomaly_cluster" for c in candidates)


def test_detections_and_timeline_against_real_schema(ops) -> None:
    services, conn = ops
    events = _populate(conn)
    page = services.detections.list(window_minutes=60)
    assert page.total == 1
    detail = services.detections.detail(page.items[0].detection_id)
    assert detail.events_found == detail.events_requested == 5
    host = events[0].host.name
    timeline = services.detections.host_timeline(host, window_minutes=10080, limit=20)
    assert timeline.known_host and timeline.detections


def test_session_is_read_only(ops, migrated_db: str) -> None:
    database = PostgresDatabase(migrated_db)
    with pytest.raises(DataSourceError) as exc:
        database.fetch_one("INSERT INTO ops.stream_queries (query_name, query_id, run_id, status, "
                           "last_event_at) VALUES ('x','x','x','active', now()) RETURNING 1")
    assert exc.value.unavailable is False
    database.close()


def test_unreachable_database_is_unavailable() -> None:
    database = PostgresDatabase("host=127.0.0.1 port=1 dbname=x user=x connect_timeout=1",
                                connect_timeout_seconds=1)
    with pytest.raises(DataSourceError) as exc:
        database.ping()
    assert exc.value.unavailable is True
