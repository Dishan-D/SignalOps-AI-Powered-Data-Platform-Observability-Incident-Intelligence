"""Non-intrusive Kafka inspection.

Nothing here joins a consumer group or commits an offset, so existing consumers
(the Spark job, the scorer) are unaffected:

* Counts come from partition watermarks and ``offsets_for_times`` — metadata
  requests, no message consumption.
* The DLQ sample reads the tail of each partition with a manually *assigned*
  consumer (no ``subscribe``, so no group rebalance) under a throwaway group id
  with auto-commit disabled.

Watermark arithmetic counts *retained offsets*. With the pipeline's idempotent,
non-transactional producers there are no control records, so that equals the
retained record count; under transactions it would be an upper bound.
"""

from __future__ import annotations

import contextlib
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from signalops.sources.errors import DataSourceError

SOURCE = "kafka"


@dataclass(frozen=True)
class KafkaRecord:
    partition: int
    offset: int
    timestamp_ms: int | None
    value: bytes | None


class KafkaInspector(Protocol):
    def topics(self) -> dict[str, int]:
        """Existing topics -> partition count."""
        ...

    def watermarks(self, topic: str) -> dict[int, tuple[int, int]]:
        """Partition -> (low, high) watermark offsets."""
        ...

    def offsets_at(self, topic: str, timestamp_ms: int) -> dict[int, int]:
        """Partition -> earliest offset whose record timestamp >= timestamp_ms.

        ``-1`` means no such record (nothing newer than the timestamp).
        """
        ...

    def tail(self, topic: str, per_partition: int, *, timeout_seconds: float) -> list[KafkaRecord]:
        """Up to ``per_partition`` most recent records from each partition."""
        ...


class ConfluentKafkaInspector:
    def __init__(self, bootstrap_servers: str, *, timeout_seconds: float = 3.0) -> None:
        self._bootstrap = bootstrap_servers
        self._timeout = timeout_seconds
        self._lock = threading.Lock()
        self._consumer: Any = None

    def _config(self) -> dict[str, Any]:
        return {
            "bootstrap.servers": self._bootstrap,
            # Never used to join a group: this consumer only ever assign()s.
            "group.id": f"signalops-inspector-{uuid.uuid4().hex[:12]}",
            "enable.auto.commit": False,
            "enable.auto.offset.store": False,
            "socket.timeout.ms": max(int(self._timeout * 1000), 2_000),
            "fetch.wait.max.ms": 100,
            "session.timeout.ms": 10_000,
            "client.id": "signalops-inspector",
        }

    def _meta_consumer(self) -> Any:
        from confluent_kafka import Consumer

        if self._consumer is None:
            self._consumer = Consumer(self._config())
        return self._consumer

    def _call(self, what: str, fn: Any) -> Any:
        from confluent_kafka import KafkaException

        with self._lock:
            try:
                return fn(self._meta_consumer())
            except KafkaException as exc:
                # A dead client keeps failing; rebuild it on the next call.
                self._reset()
                raise DataSourceError(SOURCE, f"{what} failed: {exc.args[0] if exc.args else exc}",
                                      unavailable=True) from exc
            except RuntimeError as exc:
                self._reset()
                raise DataSourceError(SOURCE, f"{what} failed: {exc}", unavailable=True) from exc

    def _reset(self) -> None:
        if self._consumer is not None:
            with contextlib.suppress(Exception):  # closing a broken client is best effort
                self._consumer.close()
        self._consumer = None

    def topics(self) -> dict[str, int]:
        def fn(consumer: Any) -> dict[str, int]:
            metadata = consumer.list_topics(timeout=self._timeout)
            return {
                name: len(topic.partitions)
                for name, topic in metadata.topics.items()
                if not name.startswith("__") and topic.error is None
            }

        return self._call("list_topics", fn)

    def _partitions(self, consumer: Any, topic: str) -> list[int]:
        metadata = consumer.list_topics(topic, timeout=self._timeout)
        entry = metadata.topics.get(topic)
        if entry is None or entry.error is not None:
            raise DataSourceError(SOURCE, f"topic {topic!r} does not exist", unavailable=False)
        return sorted(entry.partitions)

    def watermarks(self, topic: str) -> dict[int, tuple[int, int]]:
        from confluent_kafka import TopicPartition

        def fn(consumer: Any) -> dict[int, tuple[int, int]]:
            return {
                p: tuple(consumer.get_watermark_offsets(
                    TopicPartition(topic, p), timeout=self._timeout, cached=False))
                for p in self._partitions(consumer, topic)
            }

        return self._call("watermarks", fn)

    def offsets_at(self, topic: str, timestamp_ms: int) -> dict[int, int]:
        from confluent_kafka import TopicPartition

        def fn(consumer: Any) -> dict[int, int]:
            request = [TopicPartition(topic, p, timestamp_ms)
                       for p in self._partitions(consumer, topic)]
            result = consumer.offsets_for_times(request, timeout=self._timeout)
            return {tp.partition: tp.offset for tp in result}

        return self._call("offsets_for_times", fn)

    def tail(self, topic: str, per_partition: int, *, timeout_seconds: float) -> list[KafkaRecord]:
        from confluent_kafka import Consumer, KafkaException, TopicPartition

        marks = self.watermarks(topic)
        assignments = [
            TopicPartition(topic, p, max(low, high - per_partition))
            for p, (low, high) in marks.items()
            if high > low
        ]
        if not assignments:
            return []
        targets = {p: high for p, (low, high) in marks.items() if high > low}
        consumer = Consumer(self._config())
        records: list[KafkaRecord] = []
        try:
            consumer.assign(assignments)
            deadline = time.monotonic() + timeout_seconds
            remaining = dict(targets)
            while remaining and time.monotonic() < deadline:
                batch = consumer.consume(num_messages=500, timeout=0.5)
                for msg in batch:
                    if msg.error() is not None:
                        continue
                    partition, offset = msg.partition(), msg.offset()
                    if partition is None or offset is None:
                        continue
                    ts_type, ts = msg.timestamp()
                    records.append(KafkaRecord(
                        partition=partition, offset=offset,
                        timestamp_ms=ts if ts_type != 0 else None,
                        value=msg.value(),
                    ))
                    if offset + 1 >= remaining.get(partition, 0):
                        remaining.pop(partition, None)
        except KafkaException as exc:
            raise DataSourceError(SOURCE, f"tail read failed: {exc}", unavailable=True) from exc
        finally:
            consumer.close()
        return records
