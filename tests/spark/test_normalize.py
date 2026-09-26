"""Parsing, validation and DLQ routing."""

from __future__ import annotations

import datetime as dt
import json

import pytest
from pyspark.sql import functions as F
from pyspark.sql.types import (
    BinaryType,
    IntegerType,
    LongType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

from forensics.streaming.normalize import (
    flatten,
    normalize_stream,
    parse_raw,
    split_valid_invalid,
    to_dlq_records,
    validate,
)

# Mirrors the columns Spark's Kafka source produces.
KAFKA_SOURCE_SCHEMA = StructType(
    [
        StructField("key", BinaryType()),
        StructField("value", BinaryType()),
        StructField("topic", StringType()),
        StructField("partition", IntegerType()),
        StructField("offset", LongType()),
        StructField("timestamp", TimestampType()),
    ]
)


def _valid_event(**overrides) -> dict:
    event = {
        "event_id": "11111111-2222-3333-4444-555555555555",
        "timestamp": "2026-09-09T06:53:44.532+00:00",
        "category": "authentication",
        "action": "ssh_login",
        "outcome": "failure",
        "severity": 4,
        "message": "sshd[123]: Failed password for a.sharma from 203.0.113.9 port 4444 ssh2",
        "host": {"name": "web-01.corp.local", "ip": "10.20.0.10", "os_family": "linux"},
        "dataset": "linux.auth",
        "user": {"name": "a.sharma", "id": 1001, "domain": "corp.local"},
        "network": {
            "source_ip": "203.0.113.9",
            "source_port": 44444,
            "destination_ip": "10.20.0.10",
            "destination_port": 22,
            "protocol": "ssh",
            "transport": "tcp",
            "bytes_sent": 900,
            "bytes_received": 400,
            "direction": "inbound",
        },
        "labels": {},
        "schema_version": "1.0.0",
    }
    event.update(overrides)
    return event


def _kafka_df(spark, payloads: list[str | None], key: str = "web-01.corp.local"):
    rows = [
        (
            key.encode() if key else None,
            p.encode() if p is not None else None,
            "logs.raw",
            0,
            i,
            dt.datetime(2026, 9, 9, 6, 53, 45),
        )
        for i, p in enumerate(payloads)
    ]
    return spark.createDataFrame(rows, KAFKA_SOURCE_SCHEMA)


def test_valid_event_passes_validation(spark) -> None:
    df = validate(parse_raw(_kafka_df(spark, [json.dumps(_valid_event())])))
    assert df.select("validation_error").first()[0] is None


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        ("not json at all", "malformed_json"),
        ('{"event_id":', "malformed_json"),
        (json.dumps(_valid_event(timestamp="09/09/2026 06:53")), "unparseable_timestamp"),
        (json.dumps(_valid_event(category="teleportation")), "unknown_category"),
        (json.dumps(_valid_event(outcome="mostly")), "unknown_outcome"),
        (json.dumps(_valid_event(severity=99)), "severity_out_of_range"),
        (json.dumps(_valid_event(severity=-1)), "severity_out_of_range"),
    ],
)
def test_invalid_events_are_labelled_with_a_reason(spark, payload, expected_error) -> None:
    df = validate(parse_raw(_kafka_df(spark, [payload])))
    assert df.select("validation_error").first()[0] == expected_error


def test_missing_required_fields_are_rejected(spark) -> None:
    for field, expected in [
        ("event_id", "missing_event_id"),
        ("timestamp", "missing_timestamp"),
        ("host", "missing_host_name"),
        ("category", "missing_category"),
    ]:
        event = _valid_event()
        del event[field]
        df = validate(parse_raw(_kafka_df(spark, [json.dumps(event)])))
        assert df.select("validation_error").first()[0] == expected, field


def test_null_payload_is_rejected_not_crashed(spark) -> None:
    """A tombstone (null value) must dead-letter, not kill the batch."""
    df = validate(parse_raw(_kafka_df(spark, [None])))
    assert df.select("validation_error").first()[0] == "empty_payload"


def test_split_routes_each_record_exactly_once(spark) -> None:
    payloads = [
        json.dumps(_valid_event()),
        "garbage",
        json.dumps(_valid_event(category="nope")),
        json.dumps(_valid_event()),
    ]
    valid, invalid = split_valid_invalid(validate(parse_raw(_kafka_df(spark, payloads))))
    assert valid.count() == 2
    assert invalid.count() == 2


def test_dlq_record_preserves_payload_and_provenance(spark) -> None:
    _, invalid = split_valid_invalid(validate(parse_raw(_kafka_df(spark, ["broken{"]))))
    row = to_dlq_records(invalid).select(F.col("value").cast("string")).first()[0]
    record = json.loads(row)

    assert record["error"] == "malformed_json"
    assert record["source_topic"] == "logs.raw"
    assert record["source_offset"] == 0
    # Byte-for-byte, so the record can be replayed after the defect is fixed.
    assert record["payload"] == "broken{"


def test_flatten_produces_typed_analytic_columns(spark) -> None:
    valid, _ = split_valid_invalid(validate(parse_raw(_kafka_df(spark, [json.dumps(_valid_event())]))))
    row = flatten(valid).first()

    assert row["event_id"] == "11111111-2222-3333-4444-555555555555"
    assert row["host_name"] == "web-01.corp.local"
    assert row["user_name"] == "a.sharma"
    assert row["source_ip"] == "203.0.113.9"
    assert row["bytes_sent"] == 900
    assert row["category"] == "authentication"
    # event_time must be a real timestamp, not the original string.
    assert isinstance(row["event_time"], dt.datetime)
    assert row["event_time"].year == 2026


def test_event_time_is_parsed_as_utc(spark) -> None:
    """Producer timestamps are UTC; a mis-parse would shift every window."""
    valid, _ = split_valid_invalid(validate(parse_raw(_kafka_df(spark, [json.dumps(_valid_event())]))))
    row = flatten(valid).select(
        F.date_format("event_time", "yyyy-MM-dd HH:mm:ss.SSS").alias("t")
    ).first()
    assert row["t"] == "2026-09-09 06:53:44.532"


def test_non_utc_offset_is_converted_not_truncated(spark) -> None:
    event = _valid_event(timestamp="2026-09-09T06:53:44.532+05:30")
    valid, _ = split_valid_invalid(validate(parse_raw(_kafka_df(spark, [json.dumps(event)]))))
    row = valid.count(), flatten(valid).select(
        F.date_format("event_time", "HH:mm:ss").alias("t")
    ).first()
    assert row[0] == 1
    assert row[1]["t"] == "01:23:44"


def test_optional_sections_absent_become_null_not_error(spark) -> None:
    """A process event has no `network` block and must still normalise."""
    event = _valid_event(category="process", outcome="success")
    del event["network"]
    valid, invalid = split_valid_invalid(validate(parse_raw(_kafka_df(spark, [json.dumps(event)]))))
    assert invalid.count() == 0
    row = flatten(valid).first()
    assert row["source_ip"] is None
    assert row["bytes_sent"] is None
    assert row["host_name"] == "web-01.corp.local"


def test_ground_truth_is_carried_into_eval_columns(spark) -> None:
    event = _valid_event(
        labels={
            "ground_truth": {
                "is_anomaly": True,
                "scenario": "ssh_brute_force",
                "campaign_id": "abc",
                "step": 3,
            }
        }
    )
    valid, _ = split_valid_invalid(validate(parse_raw(_kafka_df(spark, [json.dumps(event)]))))
    row = flatten(valid).first()
    assert row["eval_is_anomaly"] is True
    assert row["eval_scenario"] == "ssh_brute_force"
    assert row["eval_step"] == 3


def test_normalize_stream_end_to_end(spark) -> None:
    payloads = [json.dumps(_valid_event()), "garbage", json.dumps(_valid_event())]
    normalized, rejected = normalize_stream(_kafka_df(spark, payloads))
    assert normalized.count() == 2
    assert rejected.count() == 1
    assert "event_time" in normalized.columns
