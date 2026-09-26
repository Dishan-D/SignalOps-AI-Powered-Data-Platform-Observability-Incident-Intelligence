"""Kafka publishing with retries, a dead-letter spool, and a dry-run sink.

**Where the dead letters go.** There is a subtlety worth being explicit about:
a *producer* cannot dead-letter to Kafka, because the reason it is failing is
usually that Kafka is unreachable. So this module uses two different mechanisms
for two different failure domains:

* **Producer-side (here):** after the client's own retry budget is exhausted,
  the record is written to a local append-only JSONL **spool file**. Disk is the
  only durable thing left when the broker is gone. An operator (or a Phase 2
  replay job) can re-drive that file once the cluster is healthy.
* **Consumer-side (Phase 2, Spark):** records that fail *parsing or validation*
  are perfectly deliverable, so those go to the ``logs.raw.dlq`` topic with the
  failure reason in a header. That topic is created up front by ``kafka-init``.

Confusing the two is a common design smell; keeping them separate means a broker
outage never silently discards evidence.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from forensics.common.config import KafkaSettings
from forensics.common.logging import get_logger

logger = get_logger(__name__, component="kafka")


@dataclass(slots=True)
class SinkStats:
    """Counters surfaced periodically so throughput/loss is observable."""

    produced: int = 0
    delivered: int = 0
    failed: int = 0
    dead_lettered: int = 0
    retries: int = 0
    bytes_out: int = 0

    def snapshot(self) -> dict[str, int]:
        return {
            "produced": self.produced,
            "delivered": self.delivered,
            "failed": self.failed,
            "dead_lettered": self.dead_lettered,
            "retries": self.retries,
            "bytes_out": self.bytes_out,
        }


class EventSink(Protocol):
    """Anything the producer can publish to (Kafka, stdout, a test double)."""

    stats: SinkStats

    def send(self, *, key: str, value: str, headers: dict[str, str] | None = None) -> None: ...

    def poll(self, timeout: float = 0.0) -> None: ...

    def flush(self, timeout: float = 10.0) -> int: ...

    def close(self) -> None: ...


class DeadLetterSpool:
    """Append-only JSONL file holding records Kafka refused to accept.

    Writes are ``fsync``-free by default (throughput matters more than losing
    the last few bytes on a hard kill), but each record is a complete line so a
    truncated tail costs at most one event.
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._handle: Any = None
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            # A read-only mount must not prevent the service from starting; the
            # first write attempt will log the real failure.
            logger.warning(
                "Could not create dead-letter spool directory",
                extra={"path": str(self._path.parent)},
            )

    def write(self, *, key: str, value: str, reason: str) -> None:
        record = {
            "spooled_at": time.time(),
            "key": key,
            "reason": reason,
            "payload": value,
        }
        line = json.dumps(record, separators=(",", ":")) + "\n"
        with self._lock:
            try:
                if self._handle is None:
                    self._handle = self._path.open("a", encoding="utf-8")
                self._handle.write(line)
                self._handle.flush()
            except OSError:
                # Last line of defence: if even the spool is unwritable, emit the
                # payload on stdout so the container log retains the evidence.
                logger.error(
                    "Dead-letter spool write failed; emitting payload to stdout",
                    exc_info=True,
                    extra={"path": str(self._path), "dlq_payload": value},
                )

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                try:
                    self._handle.close()
                finally:
                    self._handle = None


class StdoutSink:
    """Dry-run sink: prints records instead of publishing them.

    Lets the whole ingestion path be exercised (and unit-tested) with no broker
    and no native dependencies — ``PRODUCER_DRY_RUN=true``.
    """

    def __init__(self, topic: str) -> None:
        self._topic = topic
        self.stats = SinkStats()

    def send(self, *, key: str, value: str, headers: dict[str, str] | None = None) -> None:
        # Mirror the full Kafka record (headers included) so a dry run shows
        # exactly what would have been published.
        record = {
            "topic": self._topic,
            "key": key,
            "headers": headers or {},
            "value": json.loads(value),
        }
        print(json.dumps(record, separators=(",", ":")), flush=True)
        self.stats.produced += 1
        self.stats.delivered += 1
        self.stats.bytes_out += len(value)

    def poll(self, timeout: float = 0.0) -> None:  # noqa: ARG002 - protocol shape
        return None

    def flush(self, timeout: float = 10.0) -> int:  # noqa: ARG002 - protocol shape
        return 0  # nothing is ever buffered

    def close(self) -> None:
        return None


class KafkaSink:
    """Resilient wrapper around ``confluent_kafka.Producer``.

    Failure handling, in order:

    1. **librdkafka internal retries** — transient broker/leader errors are
       retried inside ``message.timeout.ms`` without us seeing them.
    2. **Local queue backpressure** — a full producer queue raises
       ``BufferError``. We ``poll()`` to drain delivery callbacks and retry with
       exponential backoff rather than dropping the record.
    3. **Application retry** — a delivery callback carrying an error re-produces
       the record up to ``max_delivery_retries`` times.
    4. **Dead-letter spool** — anything still failing is persisted to disk.
    """

    def __init__(
        self,
        settings: KafkaSettings,
        *,
        spool: DeadLetterSpool,
        max_delivery_retries: int = 3,
        max_enqueue_retries: int = 10,
    ) -> None:
        # Imported lazily so dry-run mode needs no native librdkafka wheel.
        try:
            from confluent_kafka import Producer
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "confluent-kafka is not installed. Install requirements.txt, or "
                "run with PRODUCER_DRY_RUN=true to use the stdout sink."
            ) from exc

        self._settings = settings
        self._spool = spool
        self._max_delivery_retries = max_delivery_retries
        self._max_enqueue_retries = max_enqueue_retries
        self.stats = SinkStats()
        self._producer = Producer(self._build_config(settings))

    @staticmethod
    def _build_config(settings: KafkaSettings) -> dict[str, Any]:
        """Map our settings onto librdkafka properties."""
        return {
            "bootstrap.servers": settings.bootstrap_servers,
            "client.id": settings.client_id,
            "security.protocol": settings.security_protocol,
            "acks": settings.acks,
            # Idempotence pins max.in.flight<=5 and retries=INT_MAX internally,
            # giving ordered, duplicate-free writes per partition.
            "enable.idempotence": settings.enable_idempotence,
            "compression.type": settings.compression_type,
            "message.timeout.ms": settings.message_timeout_ms,
            "request.timeout.ms": settings.request_timeout_ms,
            "linger.ms": settings.linger_ms,
            "batch.size": settings.batch_size,
            "queue.buffering.max.messages": settings.queue_buffering_max_messages,
            # Surface broker-level problems through our JSON logger.
            "error_cb": _log_client_error,
            "log_level": 4,
        }

    def _delivery_report(self, err: Any, msg: Any, *, attempt: int) -> None:
        """librdkafka delivery callback — runs on ``poll()``/``flush()``."""
        if err is None:
            self.stats.delivered += 1
            return

        key = msg.key().decode("utf-8", "replace") if msg.key() else ""
        value = msg.value().decode("utf-8", "replace") if msg.value() else ""
        self.stats.failed += 1

        if attempt < self._max_delivery_retries:
            self.stats.retries += 1
            logger.warning(
                "Delivery failed; retrying",
                extra={"error": str(err), "attempt": attempt + 1, "key": key},
            )
            self._enqueue(key=key, value=value, headers=None, attempt=attempt + 1)
            return

        self.stats.dead_lettered += 1
        logger.error(
            "Delivery permanently failed; writing to dead-letter spool",
            extra={"error": str(err), "attempts": attempt + 1, "key": key},
        )
        self._spool.write(key=key, value=value, reason=str(err))

    def _enqueue(
        self,
        *,
        key: str,
        value: str,
        headers: dict[str, str] | None,
        attempt: int,
    ) -> None:
        """Hand a record to librdkafka, absorbing local-queue backpressure."""
        backoff = 0.05
        for enqueue_attempt in range(self._max_enqueue_retries):
            try:
                self._producer.produce(
                    topic=self._settings.raw_logs_topic,
                    key=key.encode("utf-8"),
                    value=value.encode("utf-8"),
                    headers=list(headers.items()) if headers else None,
                    on_delivery=lambda err, msg, _a=attempt: self._delivery_report(
                        err, msg, attempt=_a
                    ),
                )
                self.stats.produced += 1
                self.stats.bytes_out += len(value)
                return
            except BufferError:
                # Local queue is full: serve delivery callbacks to free slots.
                self.stats.retries += 1
                self._producer.poll(backoff)
                backoff = min(backoff * 2, 1.0)
                if enqueue_attempt == 0:
                    logger.warning(
                        "Producer queue full; applying backpressure",
                        extra={"queue_depth": len(self._producer)},
                    )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - must never kill the loop
                logger.error("Produce call raised", exc_info=True, extra={"key": key})
                self._spool.write(key=key, value=value, reason=f"produce_error: {exc}")
                return

        self.stats.dead_lettered += 1
        logger.error(
            "Producer queue full after retries; writing to dead-letter spool",
            extra={"key": key},
        )
        self._spool.write(key=key, value=value, reason="local_queue_full")

    # -- EventSink protocol ---------------------------------------------------

    def send(self, *, key: str, value: str, headers: dict[str, str] | None = None) -> None:
        self._enqueue(key=key, value=value, headers=headers, attempt=0)

    def poll(self, timeout: float = 0.0) -> None:
        """Serve delivery callbacks. Must be called regularly by the main loop."""
        self._producer.poll(timeout)

    def flush(self, timeout: float = 10.0) -> int:
        """Block until the queue drains; returns the number still outstanding."""
        return self._producer.flush(timeout)

    def close(self) -> None:
        remaining = self.flush(timeout=15.0)
        if remaining:
            logger.error(
                "Shutting down with undelivered messages",
                extra={"undelivered": remaining},
            )
        self._spool.close()


def _log_client_error(err: Any) -> None:
    """librdkafka ``error_cb``: broker-level events (connectivity, auth)."""
    logger.warning("Kafka client error", extra={"error": str(err)})


def build_sink(settings: KafkaSettings, *, dry_run: bool, spool_path: str) -> EventSink:
    """Factory selecting the real Kafka sink or the dry-run stdout sink."""
    if dry_run:
        logger.info(
            "Dry-run mode: events will be printed, not published",
            extra={"topic": settings.raw_logs_topic},
        )
        return StdoutSink(settings.raw_logs_topic)
    return KafkaSink(settings, spool=DeadLetterSpool(spool_path))
