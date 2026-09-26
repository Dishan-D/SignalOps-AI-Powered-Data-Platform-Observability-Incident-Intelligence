"""Producer loop: pacing, shutdown, and sink interaction."""

from __future__ import annotations

import time

from forensics.common.kafka import SinkStats
from forensics.ingestion.generators import TelemetryGenerator
from forensics.ingestion.log_producer import RateLimiter, _build_headers


class RecordingSink:
    """Test double implementing the EventSink protocol."""

    def __init__(self) -> None:
        self.stats = SinkStats()
        self.records: list[tuple[str, str, dict]] = []
        self.flushed = False

    def send(self, *, key, value, headers=None):
        self.records.append((key, value, headers or {}))
        self.stats.produced += 1

    def poll(self, timeout: float = 0.0) -> None:
        return None

    def flush(self, timeout: float = 10.0) -> int:
        self.flushed = True
        return 0

    def close(self) -> None:
        self.flush()


def test_rate_limiter_holds_the_target_rate() -> None:
    limiter = RateLimiter(events_per_second=500)
    start = time.perf_counter()
    for _ in range(100):
        limiter.wait()
    elapsed = time.perf_counter() - start
    # 100 events at 500/s == 0.2s; allow generous slack for CI scheduling.
    assert 0.15 < elapsed < 0.6


def test_rate_limiter_resyncs_instead_of_bursting_after_a_stall() -> None:
    limiter = RateLimiter(events_per_second=1000, max_lag_seconds=0.05)
    limiter.wait()
    time.sleep(0.2)  # simulate a long stall (GC pause, broker timeout)
    start = time.perf_counter()
    for _ in range(50):
        limiter.wait()
    # Without resync the limiter would return instantly 50 times trying to
    # "catch up"; with it, pacing resumes immediately.
    assert time.perf_counter() - start < 0.2


def test_headers_allow_routing_without_deserialising_the_body() -> None:
    event = TelemetryGenerator(seed=4).next_events()[0]
    headers = _build_headers(event)
    assert headers["schema_version"] == event.schema_version
    assert headers["event_category"] == str(event.category)
    assert all(isinstance(v, str) for v in headers.values())


def test_sink_receives_host_keyed_records() -> None:
    sink = RecordingSink()
    generator = TelemetryGenerator(seed=6)
    for _ in range(50):
        for event in generator.next_events():
            sink.send(key=event.partition_key(), value=event.to_json(),
                      headers=_build_headers(event))
    assert sink.stats.produced == 50
    assert all(key and key.endswith(".corp.local") for key, _, _ in sink.records)
