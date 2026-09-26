"""Synthetic log producer — Kafka ingestion entrypoint.

Streams realistic security telemetry into the ``logs.raw`` topic at a
configurable rate. In a real deployment this process is replaced by Filebeat /
Auditbeat / a syslog relay; the *contract* (ECS JSON, keyed by host) stays
identical, so everything downstream is unaffected.

Run it:

    # no broker required — prints to stdout
    PRODUCER_DRY_RUN=true python -m forensics.ingestion.log_producer

    # against the Compose stack
    KAFKA_BOOTSTRAP_SERVERS=localhost:29092 python -m forensics.ingestion.log_producer
"""

from __future__ import annotations

import signal
import sys
import time
import types
import uuid

from forensics.common.config import AppSettings, ConfigError, ProducerSettings
from forensics.common.kafka import EventSink, build_sink
from forensics.common.logging import configure_logging, get_logger, set_correlation_id
from forensics.ingestion.generators import TelemetryGenerator
from forensics.ingestion.schemas import LogEvent

SERVICE_NAME = "log-producer"

logger = get_logger(__name__, component="producer")


class RateLimiter:
    """Paces the loop to a target rate using absolute deadlines.

    Sleeping ``1/rate`` per iteration accumulates drift, because the work
    between sleeps is not free. Tracking the next deadline instead keeps the
    long-run average on target. If we fall more than ``max_lag`` behind (a GC
    pause, a broker stall) the schedule is resynchronised rather than trying to
    "catch up" with an unbounded burst.
    """

    def __init__(self, events_per_second: float, *, max_lag_seconds: float = 1.0) -> None:
        self._interval = 1.0 / events_per_second
        self._max_lag = max_lag_seconds
        self._next_deadline = time.perf_counter()

    def wait(self, events: int = 1) -> None:
        self._next_deadline += self._interval * events
        delay = self._next_deadline - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
        elif delay < -self._max_lag:
            logger.debug("Rate limiter lagging; resynchronising", extra={"lag_s": -delay})
            self._next_deadline = time.perf_counter()


class GracefulShutdown:
    """Flips a flag on SIGINT/SIGTERM so the loop can drain and flush.

    Killing a producer mid-batch is how you lose evidence: unflushed records sit
    in librdkafka's queue and die with the process. Handling the signal lets us
    exit through ``sink.close()``, which flushes.
    """

    def __init__(self) -> None:
        self.requested = False
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)

    def _handle(self, signum: int, _frame: types.FrameType | None) -> None:
        logger.info("Shutdown signal received", extra={"signal": signal.Signals(signum).name})
        self.requested = True


def _build_headers(event: LogEvent) -> dict[str, str]:
    """Kafka headers let consumers route/filter without deserialising the body."""
    return {
        "schema_version": event.schema_version,
        "event_category": str(event.category),
        "dataset": event.dataset,
        "producer": SERVICE_NAME,
    }


def run(settings: AppSettings, producer_cfg: ProducerSettings) -> int:
    """Main loop. Returns a process exit code."""
    generator = TelemetryGenerator(
        host_count=producer_cfg.host_count,
        user_count=producer_cfg.user_count,
        anomaly_rate=producer_cfg.anomaly_rate,
        seed=producer_cfg.seed,
    )
    limiter = RateLimiter(producer_cfg.events_per_second)
    shutdown = GracefulShutdown()
    sink: EventSink = build_sink(
        settings.kafka,
        dry_run=producer_cfg.dry_run,
        spool_path=producer_cfg.dlq_spool_path,
    )

    logger.info(
        "Producer starting",
        extra={
            "topic": settings.kafka.raw_logs_topic,
            "bootstrap_servers": settings.kafka.bootstrap_servers,
            "events_per_second": producer_cfg.events_per_second,
            "anomaly_rate": producer_cfg.anomaly_rate,
            "max_events": producer_cfg.max_events or "unbounded",
            "dry_run": producer_cfg.dry_run,
            "seed": producer_cfg.seed,
        },
    )

    emitted = 0
    last_stats = time.monotonic()
    last_produced = 0
    exit_code = 0

    try:
        while not shutdown.requested:
            if producer_cfg.max_events and emitted >= producer_cfg.max_events:
                logger.info("Reached max_events; stopping", extra={"emitted": emitted})
                break

            for event in generator.next_events():
                sink.send(
                    key=event.partition_key(),
                    value=event.to_json(),
                    headers=_build_headers(event),
                )
                emitted += 1

            # Serve delivery callbacks without blocking the pacing loop.
            sink.poll(0.0)
            limiter.wait()

            now = time.monotonic()
            if now - last_stats >= producer_cfg.stats_interval_seconds:
                snapshot = sink.stats.snapshot()
                # Rate over the interval, not since process start: a cumulative
                # counter divided by a window length is a meaningless number.
                elapsed = max(now - last_stats, 1e-9)
                interval_produced = snapshot["produced"] - last_produced
                logger.info(
                    "Producer stats",
                    extra={
                        **snapshot,
                        "emitted_total": emitted,
                        "interval_seconds": round(elapsed, 2),
                        "throughput_eps": round(interval_produced / elapsed, 2),
                    },
                )
                last_stats = now
                last_produced = snapshot["produced"]
    except Exception:  # noqa: BLE001 - top-level guard; we still want a clean flush
        logger.critical("Unhandled error in producer loop", exc_info=True)
        exit_code = 1
    finally:
        logger.info("Flushing sink before exit", extra={"emitted_total": emitted})
        sink.close()
        logger.info("Producer stopped", extra={**sink.stats.snapshot(), "emitted_total": emitted})

    return exit_code


def main() -> int:
    try:
        settings = AppSettings.from_env(SERVICE_NAME)
        producer_cfg = ProducerSettings.from_env()
    except ConfigError as exc:
        # Logging is not configured yet, so write a plain line to stderr.
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    # In dry-run the stdout stream *is* the event feed, so operational logs
    # must go to stderr or a consumer piping us into jq gets a mixed stream.
    configure_logging(
        service=settings.service_name,
        environment=settings.environment,
        level=settings.log_level,
        stream=sys.stderr if producer_cfg.dry_run else sys.stdout,
    )
    # One id per producer run ties every log line from this process together.
    set_correlation_id(f"run-{uuid.uuid4().hex[:12]}")
    return run(settings, producer_cfg)


if __name__ == "__main__":
    raise SystemExit(main())
