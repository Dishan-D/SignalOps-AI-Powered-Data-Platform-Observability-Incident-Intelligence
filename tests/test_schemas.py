"""Wire-format guarantees other services depend on."""

from __future__ import annotations

import datetime as dt
import json

from forensics.ingestion.schemas import (
    EventCategory,
    EventOutcome,
    HostFields,
    LogEvent,
)


def _event(**overrides: object) -> LogEvent:
    base = {
        "event_id": LogEvent.new_id(),
        "timestamp": LogEvent.format_timestamp(dt.datetime(2026, 1, 1, 12, 0)),
        "category": EventCategory.PROCESS,
        "action": "process_started",
        "outcome": EventOutcome.SUCCESS,
        "severity": 6,
        "message": "audit: type=EXECVE",
        "host": HostFields(name="web-01.corp.local", ip="10.20.0.10"),
        "dataset": "linux.audit",
    }
    base.update(overrides)
    return LogEvent(**base)  # type: ignore[arg-type]


def test_timestamp_is_utc_rfc3339() -> None:
    naive = dt.datetime(2026, 1, 1, 12, 0, 0)
    assert LogEvent.format_timestamp(naive).endswith("+00:00")


def test_aware_timestamp_is_converted_not_relabelled() -> None:
    eastern = dt.timezone(dt.timedelta(hours=-5))
    aware = dt.datetime(2026, 1, 1, 12, 0, tzinfo=eastern)
    assert LogEvent.format_timestamp(aware).startswith("2026-01-01T17:00")


def test_json_round_trips_and_prunes_empty_branches() -> None:
    payload = json.loads(_event().to_json())
    assert payload["category"] == "process"
    # Unset optional sections must be absent, not null.
    assert "network" not in payload
    assert "process" not in payload


def test_partition_key_is_the_hostname() -> None:
    event = _event()
    assert event.partition_key() == "web-01.corp.local"
    assert event.partition_key() == json.loads(event.to_json())["host"]["name"]


def test_enums_serialise_as_plain_strings() -> None:
    # StrEnum members must not leak "EventCategory.PROCESS" onto the wire.
    raw = _event().to_json()
    assert "EventCategory" not in raw
    assert '"outcome":"success"' in raw


def test_event_ids_are_unique() -> None:
    assert len({LogEvent.new_id() for _ in range(1000)}) == 1000
