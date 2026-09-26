"""Sequence construction: per-host grouping, ordering, windowing, leakage."""

from __future__ import annotations

import datetime as dt

import pytest

from forensics.inference.sequences import (
    EventRecord,
    SequenceBuilder,
    to_records,
)
from forensics.inference.vocabulary import PAD_ID, UNK_ID
from forensics.ingestion.generators import TelemetryGenerator

BASE = dt.datetime(2026, 9, 9, 12, 0, tzinfo=dt.UTC)


def _record(host: str, offset: int, message: str = "svc started ok", **kw) -> EventRecord:
    return EventRecord(
        event_id=f"{host}-{offset}",
        host_name=host,
        timestamp=BASE + dt.timedelta(seconds=offset),
        message=message,
        outcome=kw.pop("outcome", "success"),
        **kw,
    )


def test_windows_never_mix_hosts() -> None:
    """Interleaving two machines would manufacture transitions that never
    happened."""
    records = [_record("a", i) for i in range(20)] + [_record("b", i) for i in range(20)]
    builder = SequenceBuilder(window_size=8, stride=4)
    windows = builder.fit(records)

    assert windows
    for window in windows:
        assert window.host_name in {"a", "b"}
        assert all(window.host_name in e for e in window.event_ids)


def test_records_are_ordered_by_time_within_a_host() -> None:
    records = [_record("a", i) for i in reversed(range(16))]
    builder = SequenceBuilder(window_size=8, stride=8)
    window = builder.fit(records)[0]
    assert window.start_time < window.end_time


def test_short_host_still_produces_a_padded_window() -> None:
    """A quiet host is where a slow compromise hides; dropping it blinds us."""
    builder = SequenceBuilder(window_size=8, stride=4)
    windows = builder.fit([_record("quiet", i) for i in range(3)])

    assert len(windows) == 1
    assert len(windows[0].token_ids) == 8
    assert windows[0].token_ids.count(PAD_ID) == 5


def test_stride_controls_overlap() -> None:
    records = [_record("a", i) for i in range(20)]
    dense = SequenceBuilder(window_size=8, stride=1).fit(records)
    sparse = SequenceBuilder(window_size=8, stride=8).fit(records)
    assert len(dense) > len(sparse)


def test_window_is_anomalous_if_any_event_is() -> None:
    records = [_record("a", i) for i in range(8)]
    records[3].is_anomaly = True
    records[3].scenario = "reverse_shell"

    window = SequenceBuilder(window_size=8, stride=8).fit(records)[0]
    assert window.is_anomaly
    assert window.scenarios == ("reverse_shell",)


def test_labels_never_reach_the_token_ids() -> None:
    """Ground truth is carried for evaluation and must not be an input."""
    benign = [_record("a", i) for i in range(8)]
    labelled = [_record("a", i) for i in range(8)]
    for record in labelled:
        record.is_anomaly = True
        record.scenario = "ssh_brute_force"

    tokens_benign = SequenceBuilder(window_size=8, stride=8).fit(benign)[0].token_ids
    tokens_labelled = SequenceBuilder(window_size=8, stride=8).fit(labelled)[0].token_ids
    assert tokens_benign == tokens_labelled


def test_transform_maps_unknown_messages_to_unk() -> None:
    builder = SequenceBuilder(window_size=4, stride=4)
    builder.fit([_record("a", i) for i in range(8)])

    windows = builder.transform(
        [_record("a", i, message="completely different shape of line here now") for i in range(4)]
    )
    assert UNK_ID in windows[0].token_ids


def test_transform_does_not_grow_the_vocabulary() -> None:
    builder = SequenceBuilder(window_size=4, stride=4)
    builder.fit([_record("a", i) for i in range(8)])
    size = builder.vocabulary.size

    builder.transform([_record("a", i, message="brand new never seen message") for i in range(4)])
    assert builder.vocabulary.size == size


def test_fit_freezes_the_vocabulary() -> None:
    builder = SequenceBuilder(window_size=4, stride=4)
    builder.fit([_record("a", i) for i in range(8)])
    assert builder.vocabulary.frozen


@pytest.mark.parametrize(("window", "stride"), [(1, 1), (8, 0), (8, 9)])
def test_invalid_geometry_is_rejected(window: int, stride: int) -> None:
    with pytest.raises(ValueError):
        SequenceBuilder(window_size=window, stride=stride)


def test_real_generated_stream_builds_sequences() -> None:
    generator = TelemetryGenerator(host_count=8, user_count=20, anomaly_rate=0.05, seed=5)
    events = []
    while len(events) < 8000:
        events.extend(generator.next_events())

    builder = SequenceBuilder(window_size=16, stride=4)
    windows = builder.fit(to_records(events[:8000]))

    assert windows
    assert all(len(w.token_ids) == 16 for w in windows)
    assert any(w.is_anomaly for w in windows)
    assert builder.vocabulary.size < 60


def test_benign_only_stream_has_no_anomalous_windows() -> None:
    """The training set must be clean, or one-class training is meaningless."""
    generator = TelemetryGenerator(host_count=6, anomaly_rate=0.0, seed=9)
    events = []
    while len(events) < 4000:
        events.extend(generator.next_events())

    windows = SequenceBuilder(window_size=16, stride=8).fit(to_records(events[:4000]))
    assert not any(w.is_anomaly for w in windows)
