"""Scorer plumbing: per-host buffering, message parsing, alert shape.

The consumer loop itself needs a live broker and is exercised by the Compose
stack; everything it depends on is pure and tested here.
"""

from __future__ import annotations

import datetime as dt

from forensics.inference.evaluate import Threshold
from forensics.inference.scorer import (
    HostWindowBuffer,
    detection_payload,
    record_from_normalized,
)
from forensics.inference.sequences import EventRecord, SequenceWindow

BASE = dt.datetime(2026, 9, 9, 12, 0, tzinfo=dt.UTC)


def _record(host: str, offset: int) -> EventRecord:
    return EventRecord(
        event_id=f"{host}-{offset}",
        host_name=host,
        timestamp=BASE + dt.timedelta(seconds=offset),
        message="svc started",
        outcome="success",
    )


def test_no_window_until_the_buffer_fills() -> None:
    buffer = HostWindowBuffer(window_size=4, stride=2, max_hosts=10)
    assert buffer.add(_record("a", 0)) is None
    assert buffer.add(_record("a", 1)) is None
    assert buffer.add(_record("a", 2)) is None
    assert buffer.add(_record("a", 3)) is not None


def test_windows_then_emit_every_stride() -> None:
    buffer = HostWindowBuffer(window_size=4, stride=2, max_hosts=10)
    emitted = [buffer.add(_record("a", i)) is not None for i in range(10)]
    # First at index 3, then every 2 thereafter.
    assert emitted[:4] == [False, False, False, True]
    assert emitted[4:] == [False, True, False, True, False, True]


def test_hosts_are_buffered_independently() -> None:
    buffer = HostWindowBuffer(window_size=3, stride=3, max_hosts=10)
    for i in range(2):
        buffer.add(_record("a", i))
        buffer.add(_record("b", i))
    assert buffer.add(_record("a", 2)) is not None
    assert buffer.tracked_hosts == 2

    completed = buffer.add(_record("b", 2))
    assert completed is not None
    # A window must contain only its own host's events.
    assert all(r.host_name == "b" for r in completed)


def test_idle_hosts_are_evicted_at_capacity() -> None:
    """An unbounded dict of buffers is a slow leak in any estate with churn."""
    buffer = HostWindowBuffer(window_size=4, stride=2, max_hosts=3)
    for index in range(10):
        buffer.add(_record(f"host-{index}", 0))

    assert buffer.tracked_hosts <= 3
    assert buffer.evicted_hosts >= 7


def test_active_hosts_survive_eviction() -> None:
    """LRU: the host still reporting must not be the one dropped."""
    buffer = HostWindowBuffer(window_size=4, stride=2, max_hosts=2)
    buffer.add(_record("busy", 0))
    buffer.add(_record("idle", 0))
    for index in range(1, 5):
        buffer.add(_record("busy", index))
        buffer.add(_record(f"new-{index}", 0))

    assert buffer.records_for("busy"), "the active host was evicted"


def test_completed_window_carries_its_records_in_order() -> None:
    buffer = HostWindowBuffer(window_size=3, stride=3, max_hosts=10)
    completed = None
    for index in range(3):
        result = buffer.add(_record("a", index))
        if result is not None:
            completed = result

    assert completed is not None
    assert [r.event_id for r in completed] == ["a-0", "a-1", "a-2"]
    assert completed[0].timestamp < completed[-1].timestamp


# --------------------------------------------------------------------------- #
# Message parsing                                                              #
# --------------------------------------------------------------------------- #

def _payload(**overrides) -> dict:
    payload = {
        "event_id": "65d78cbd-03f2-41a5-a03e-f1cb103776c6",
        "host_name": "web-01.corp.local",
        "event_time": "2026-09-09T12:00:00+00:00",
        "message": "sshd[1]: Failed password for a from 10.0.0.1 port 2 ssh2",
        "outcome": "failure",
    }
    payload.update(overrides)
    return payload


def test_valid_message_parses() -> None:
    record = record_from_normalized(_payload())
    assert record is not None
    assert record.host_name == "web-01.corp.local"
    assert record.outcome == "failure"


def test_epoch_millis_timestamp_is_accepted() -> None:
    record = record_from_normalized(_payload(event_time=1789000000000))
    assert record is not None
    assert record.timestamp.year > 2020


def test_missing_fields_are_skipped_not_fatal() -> None:
    """A malformed message must not take the consumer down."""
    for missing in ("host_name", "message", "event_time"):
        assert record_from_normalized(_payload(**{missing: None})) is None
    assert record_from_normalized({}) is None
    assert record_from_normalized(None) is None


def test_unparseable_timestamp_is_skipped() -> None:
    assert record_from_normalized(_payload(event_time="last tuesday")) is None


def test_ground_truth_in_the_payload_is_ignored() -> None:
    """The scorer must behave identically on labelled and unlabelled data."""
    plain = record_from_normalized(_payload())
    labelled = record_from_normalized(
        _payload(eval_is_anomaly=True, eval_scenario="ssh_brute_force")
    )
    assert plain is not None and labelled is not None
    assert labelled.is_anomaly is False
    assert labelled.scenario is None
    assert plain.message == labelled.message


def test_missing_outcome_defaults_to_unknown() -> None:
    record = record_from_normalized(_payload(outcome=None))
    assert record is not None
    assert record.outcome == "unknown"


# --------------------------------------------------------------------------- #
# Alert shape                                                                  #
# --------------------------------------------------------------------------- #

def _window() -> SequenceWindow:
    return SequenceWindow(
        host_name="web-01",
        token_ids=[3, 4, 5, 6],
        start_time=BASE,
        end_time=BASE + dt.timedelta(minutes=1),
        event_ids=["e1", "e2"],
    )


def test_detection_payload_is_json_serialisable_and_complete() -> None:
    import json

    threshold = Threshold(cuts={"max_nll": 5.0, "mean_nll": 2.0}, target_false_positive_rate=0.01)
    payload = detection_payload(
        _window(), {"max_nll": 7.5, "mean_nll": 1.0}, threshold, model_version="logbert-0.1.0"
    )

    assert payload["flagged"] is True
    assert payload["score"] == 7.5 / 5.0
    assert payload["event_ids"] == ["e1", "e2"]
    assert payload["model_version"] == "logbert-0.1.0"
    # Thresholds ride along so a verdict is re-evaluable later.
    assert payload["thresholds"] == threshold.cuts
    json.dumps(payload)


def test_below_every_cut_is_not_flagged() -> None:
    threshold = Threshold(cuts={"max_nll": 5.0, "mean_nll": 2.0}, target_false_positive_rate=0.01)
    payload = detection_payload(
        _window(), {"max_nll": 1.0, "mean_nll": 0.5}, threshold, model_version="v"
    )
    assert payload["flagged"] is False
    assert payload["score"] < 1.0


def test_any_signal_alone_can_flag() -> None:
    """OR, not AND: the signals catch different things."""
    threshold = Threshold(cuts={"max_nll": 5.0, "mean_nll": 2.0}, target_false_positive_rate=0.01)
    only_mean = detection_payload(
        _window(), {"max_nll": 0.1, "mean_nll": 9.0}, threshold, model_version="v"
    )
    assert only_mean["flagged"] is True
