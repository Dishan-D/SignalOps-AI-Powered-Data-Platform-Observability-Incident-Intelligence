"""Helpers shared by the operational services."""

from __future__ import annotations

import datetime as dt
import threading
import time
from collections.abc import Callable
from typing import Any, TypeVar

from signalops.models import Metric, ValueState
from signalops.sources.errors import DataSourceError
from signalops.sources.kafka import KafkaInspector

T = TypeVar("T")

#: Upper bounds applied to every caller-supplied window and page size.
MAX_WINDOW_MINUTES = 7 * 24 * 60
MAX_LIMIT = 500


def clamp_window(minutes: int) -> int:
    if minutes < 1 or minutes > MAX_WINDOW_MINUTES:
        raise ValueError(f"window_minutes must be within 1..{MAX_WINDOW_MINUTES}")
    return minutes


def seconds_since(moment: dt.datetime | None, now: dt.datetime) -> float | None:
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return max(0.0, (now - moment).total_seconds())


def state_for(exc: DataSourceError) -> ValueState:
    return ValueState.unavailable if exc.unavailable else ValueState.error


def measure(
    name: str,
    source: str,
    fn: Callable[[], float | int | None],
    *,
    unit: str | None = None,
    window_minutes: int | None = None,
    unknown_detail: str = "no data to compute from",
    detail: str | None = None,
) -> Metric:
    """Run ``fn`` and wrap the outcome as a :class:`Metric`.

    ``None`` means the source answered with nothing to measure (unknown); a
    :class:`DataSourceError` becomes unavailable/error. Neither ever becomes 0.
    """
    try:
        value = fn()
    except DataSourceError as exc:
        return Metric.missing(name, state_for(exc), source=source, detail=exc.message,
                              unit=unit, window_minutes=window_minutes)
    if value is None:
        return Metric.missing(name, ValueState.unknown, source=source, detail=unknown_detail,
                              unit=unit, window_minutes=window_minutes)
    return Metric.ok(name, float(value), source=source, unit=unit,
                     window_minutes=window_minutes, detail=detail)


def kafka_records_since(kafka: KafkaInspector, topic: str, since: dt.datetime) -> int:
    """Records appended to ``topic`` at or after ``since`` (by record timestamp).

    Pure offset arithmetic — no message is read. If retention has already
    removed records newer than ``since`` the result is a lower bound.
    """
    marks = kafka.watermarks(topic)
    offsets = kafka.offsets_at(topic, int(since.timestamp() * 1000))
    total = 0
    for partition, (low, high) in marks.items():
        start = offsets.get(partition, -1)
        if start is None or start < 0:
            continue  # no record at or after `since` in this partition
        total += max(0, high - max(start, low))
    return total


def kafka_retained(kafka: KafkaInspector, topic: str) -> int:
    return sum(max(0, high - low) for low, high in kafka.watermarks(topic).values())


class TTLCache:
    """Tiny per-key TTL cache to keep dashboard polling off the database.

    Results carry their own ``generated_at``/``checked_at`` timestamps, so a
    cached answer is visibly as old as it is.
    """

    def __init__(self, ttl_seconds: float) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._entries: dict[Any, tuple[float, Any]] = {}

    def get_or_compute(self, key: Any, compute: Callable[[], T]) -> T:
        if self._ttl <= 0:
            return compute()
        now = time.monotonic()
        with self._lock:
            hit = self._entries.get(key)
            if hit is not None and now - hit[0] < self._ttl:
                return hit[1]
        value = compute()
        with self._lock:
            self._entries[key] = (time.monotonic(), value)
            if len(self._entries) > 256:
                oldest = min(self._entries, key=lambda k: self._entries[k][0])
                self._entries.pop(oldest, None)
        return value

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
