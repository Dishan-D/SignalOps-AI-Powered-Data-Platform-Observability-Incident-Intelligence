"""Streaming detection service.

Consumes ``logs.normalized``, maintains a rolling window per host, scores each
completed window with the trained model, and writes verdicts to Kafka and
PostgreSQL.

    logs.normalized ──► per-host buffer ──► LogBERT ──┬──► alerts.anomalies
                                                      └──► analytics.detections

Offsets are committed only after a batch has been written. That makes the
service at-least-once: a crash mid-batch replays those messages, and the
``detections_unique_window`` constraint turns the replay into a no-op rather
than a duplicate alert.
"""

from __future__ import annotations

import datetime as dt
import json
import signal
import sys
import types
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any

from forensics.common.config import (
    AppSettings,
    ConfigError,
    KafkaSettings,
    env_bool,
    env_float,
    env_int,
    env_str,
)
from forensics.common.logging import configure_logging, get_logger
from forensics.inference.evaluate import Threshold, score_windows
from forensics.inference.sequences import EventRecord, SequenceWindow

SERVICE_NAME = "anomaly-scorer"

logger = get_logger(__name__, component="scorer")


@dataclass(frozen=True, slots=True)
class ScorerSettings:
    model_path: str
    consumer_group: str
    normalized_topic: str
    alerts_topic: str
    # Bounds how many hosts are tracked at once. An unbounded dict of buffers is
    # a slow memory leak in any estate with churn (containers, ephemeral VMs).
    max_tracked_hosts: int
    batch_size: int
    flush_interval_seconds: float
    target_false_positive_rate: float
    postgres_enabled: bool
    postgres_dsn: str
    model_version: str

    @classmethod
    def from_env(cls) -> ScorerSettings:
        return cls(
            model_path=env_str("SCORER_MODEL_PATH", "/app/artifacts/logbert"),
            consumer_group=env_str("SCORER_CONSUMER_GROUP", "forensics-scorer"),
            normalized_topic=env_str("KAFKA_NORMALIZED_TOPIC", "logs.normalized"),
            alerts_topic=env_str("KAFKA_ALERTS_TOPIC", "alerts.anomalies"),
            max_tracked_hosts=env_int("SCORER_MAX_TRACKED_HOSTS", 5_000),
            batch_size=env_int("SCORER_BATCH_SIZE", 128),
            flush_interval_seconds=env_float("SCORER_FLUSH_INTERVAL_SECONDS", 5.0),
            target_false_positive_rate=env_float("SCORER_TARGET_FPR", 0.01),
            postgres_enabled=env_bool("SCORER_POSTGRES_ENABLED", False),
            postgres_dsn=env_str("SCORER_POSTGRES_DSN", ""),
            model_version=env_str("SCORER_MODEL_VERSION", "logbert-0.1.0"),
        )


class HostWindowBuffer:
    """Rolling per-host buffers that emit completed windows.

    Bounded by host count with LRU eviction: a host that stops reporting is
    dropped rather than pinning its buffer forever.
    """

    def __init__(self, *, window_size: int, stride: int, max_hosts: int) -> None:
        self._window_size = window_size
        self._stride = stride
        self._max_hosts = max_hosts
        self._buffers: OrderedDict[str, deque[EventRecord]] = OrderedDict()
        self._since_emit: dict[str, int] = {}
        self.evicted_hosts = 0

    def add(self, record: EventRecord) -> list[EventRecord] | None:
        """Append a record; return the window's records when one completes.

        Returns records rather than a :class:`SequenceWindow` deliberately: the
        buffer does not own the vocabulary, so it cannot encode tokens, and
        returning a half-built window with an empty ``token_ids`` invites the
        caller to treat a perfectly valid window as falsy.
        """
        buffer = self._buffers.get(record.host_name)
        if buffer is None:
            buffer = deque(maxlen=self._window_size)
            self._buffers[record.host_name] = buffer
            self._since_emit[record.host_name] = 0
            self._evict_if_needed()
        self._buffers.move_to_end(record.host_name)

        buffer.append(record)
        self._since_emit[record.host_name] += 1

        if len(buffer) < self._window_size:
            return None
        if self._since_emit[record.host_name] < self._stride:
            return None

        self._since_emit[record.host_name] = 0
        return list(buffer)

    def _evict_if_needed(self) -> None:
        while len(self._buffers) > self._max_hosts:
            host, _ = self._buffers.popitem(last=False)
            self._since_emit.pop(host, None)
            self.evicted_hosts += 1
            logger.warning(
                "Evicted idle host buffer at capacity",
                extra={"host": host, "max_tracked_hosts": self._max_hosts},
            )

    def records_for(self, host: str) -> list[EventRecord]:
        return list(self._buffers.get(host, ()))

    @property
    def tracked_hosts(self) -> int:
        return len(self._buffers)


def record_from_normalized(payload: dict[str, Any]) -> EventRecord | None:
    """Build an :class:`EventRecord` from a ``logs.normalized`` message.

    Returns ``None`` for anything missing the fields scoring requires, so a
    malformed message is skipped and counted rather than crashing the consumer.

    Ground-truth columns present in the payload are deliberately ignored: the
    scorer must behave identically whether or not the data happens to be
    labelled.
    """
    try:
        host = payload["host_name"]
        message = payload["message"]
        raw_time = payload["event_time"]
    except (KeyError, TypeError):
        return None
    if not host or not message or not raw_time:
        return None

    try:
        timestamp = (
            dt.datetime.fromisoformat(raw_time)
            if isinstance(raw_time, str)
            else dt.datetime.fromtimestamp(raw_time / 1000, tz=dt.timezone.utc)
        )
    except (ValueError, OSError, TypeError):
        return None

    return EventRecord(
        event_id=str(payload.get("event_id") or ""),
        host_name=str(host),
        timestamp=timestamp,
        message=str(message),
        outcome=str(payload.get("outcome") or "unknown"),
    )


def detection_payload(
    window: SequenceWindow,
    signals: dict[str, float],
    threshold: Threshold,
    *,
    model_version: str,
) -> dict[str, Any]:
    """The alert record published to Kafka and stored in Postgres."""
    return {
        "model_version": model_version,
        "host_name": window.host_name,
        "window_start": window.start_time.isoformat(),
        "window_end": window.end_time.isoformat(),
        "signals": signals,
        "score": threshold.normalised(signals),
        "flagged": threshold.flags(signals),
        "thresholds": threshold.cuts,
        "event_ids": window.event_ids,
    }


class GracefulShutdown:
    """Flips a flag on SIGINT/SIGTERM so the consumer can flush and commit."""

    def __init__(self) -> None:
        self.requested = False
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)

    def _handle(self, signum: int, _frame: types.FrameType | None) -> None:
        logger.info("Shutdown signal received", extra={"signal": signal.Signals(signum).name})
        self.requested = True


class DetectionWriter:
    """Writes detections to PostgreSQL, if enabled."""

    def __init__(self, dsn: str, *, model_version: str) -> None:
        import psycopg

        self._connection = psycopg.connect(dsn, autocommit=True)
        self._model_version = model_version
        self._run_id: int | None = None

    def ensure_run(self, *, window_size: int, stride: int, vocabulary_size: int,
                   template_count: int, thresholds: dict[str, float],
                   target_fpr: float) -> int:
        """Register this model version, or reuse the existing row."""
        if self._run_id is not None:
            return self._run_id
        with self._connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO analytics.model_runs
                    (model_version, window_size, stride, vocabulary_size,
                     template_count, thresholds, target_fpr)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (model_version) DO UPDATE SET thresholds = EXCLUDED.thresholds
                RETURNING run_id
                """,
                (self._model_version, window_size, stride, vocabulary_size,
                 template_count, json.dumps(thresholds), target_fpr),
            )
            row = cur.fetchone()
            if row is None:
                # RETURNING yields no row only if the upsert matched nothing,
                # which would mean detections had no run to reference.
                raise RuntimeError(
                    f"could not register model run {self._model_version!r}"
                )
            self._run_id = int(row[0])
        return self._run_id

    def write(self, detections: list[dict[str, Any]]) -> int:
        if not detections or self._run_id is None:
            return 0
        months = {d["window_start"][:7] + "-01" for d in detections}
        with self._connection.cursor() as cur:
            for month in months:
                cur.execute("SELECT analytics.ensure_detection_partition(%s::date)", (month,))
            cur.executemany(
                """
                INSERT INTO analytics.detections
                    (run_id, host_name, window_start, window_end, signals, score,
                     flagged, event_ids)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (run_id, host_name, window_start) DO NOTHING
                """,
                [
                    (
                        self._run_id, d["host_name"], d["window_start"], d["window_end"],
                        json.dumps(d["signals"]), d["score"], d["flagged"],
                        [e for e in d["event_ids"] if e],
                    )
                    for d in detections
                ],
            )
        return len(detections)

    def close(self) -> None:
        self._connection.close()


def main() -> int:  # pragma: no cover - requires a live broker
    """Consume, score, publish. Exercised by the Compose stack, not by tests."""
    try:
        settings = AppSettings.from_env(SERVICE_NAME)
        scorer_settings = ScorerSettings.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    configure_logging(
        service=settings.service_name,
        environment=settings.environment,
        level=settings.log_level,
    )
    return run(settings.kafka, scorer_settings)


def run(kafka: KafkaSettings, settings: ScorerSettings) -> int:  # pragma: no cover
    import time

    from confluent_kafka import Consumer, Producer

    from forensics.inference.train import load_bundle
    from forensics.inference.vocabulary import UNK_ID, LogKey

    model, builder, metadata = load_bundle(settings.model_path)
    logger.info(
        "Loaded model bundle",
        extra={
            "path": settings.model_path,
            "window_size": builder.window_size,
            "vocabulary": builder.vocabulary.size,
            "templates": builder.miner.vocabulary_size,
        },
    )

    thresholds = metadata.get("thresholds")
    if not thresholds:
        # Without stored cuts the service cannot decide anything; refusing is
        # safer than inventing a threshold and emitting meaningless verdicts.
        logger.critical(
            "Model bundle has no calibrated thresholds; run scripts/train_detector.py",
            extra={"path": settings.model_path},
        )
        return 2
    threshold = Threshold(
        cuts=dict(thresholds),
        target_false_positive_rate=settings.target_false_positive_rate,
    )

    consumer = Consumer({
        "bootstrap.servers": kafka.bootstrap_servers,
        "group.id": settings.consumer_group,
        "auto.offset.reset": "latest",
        # Manual commit: offsets advance only after a batch is written.
        "enable.auto.commit": False,
        "max.poll.interval.ms": 600_000,
    })
    producer = Producer({
        "bootstrap.servers": kafka.bootstrap_servers,
        "acks": kafka.acks,
        "enable.idempotence": kafka.enable_idempotence,
        "compression.type": kafka.compression_type,
    })
    consumer.subscribe([settings.normalized_topic])

    writer: DetectionWriter | None = None
    if settings.postgres_enabled and settings.postgres_dsn:
        writer = DetectionWriter(settings.postgres_dsn, model_version=settings.model_version)
        writer.ensure_run(
            window_size=builder.window_size, stride=builder.stride,
            vocabulary_size=builder.vocabulary.size,
            template_count=builder.miner.vocabulary_size,
            thresholds=threshold.cuts,
            target_fpr=settings.target_false_positive_rate,
        )

    buffers = HostWindowBuffer(
        window_size=builder.window_size, stride=builder.stride,
        max_hosts=settings.max_tracked_hosts,
    )
    shutdown = GracefulShutdown()
    pending: list[SequenceWindow] = []
    skipped = alerts = scored = 0
    last_flush = time.monotonic()

    def encode(records: list[EventRecord]) -> SequenceWindow:
        """Turn a completed buffer into a scored-ready window.

        Done at capture time, not at flush time: the host's buffer keeps moving,
        so encoding later would read whatever it contains then, not what the
        window actually was.
        """
        tokens = [
            builder.vocabulary.lookup(LogKey(match.cluster_id, record.outcome or "unknown"))
            if (match := builder.miner.match(record.message)) is not None
            else UNK_ID
            for record in records
        ]
        return SequenceWindow(
            host_name=records[0].host_name,
            token_ids=tokens[: builder.window_size],
            start_time=records[0].timestamp,
            end_time=records[-1].timestamp,
            event_ids=[r.event_id for r in records],
        )

    def flush() -> None:
        nonlocal pending, alerts, scored
        if not pending:
            return
        results = score_windows(model, pending)
        detections = []
        for index, window in enumerate(pending):
            signals = {name: results[name][index] for name in threshold.cuts}
            detections.append(
                detection_payload(window, signals, threshold,
                                  model_version=settings.model_version)
            )
        scored += len(detections)

        for detection in detections:
            if detection["flagged"]:
                alerts += 1
                producer.produce(
                    topic=settings.alerts_topic,
                    key=detection["host_name"].encode(),
                    value=json.dumps(detection).encode(),
                )
        producer.flush(10.0)
        if writer is not None:
            writer.write(detections)

        consumer.commit(asynchronous=False)
        pending = []

    logger.info("Scorer started", extra={"topic": settings.normalized_topic})
    try:
        while not shutdown.requested:
            message = consumer.poll(1.0)
            now = time.monotonic()

            if message is not None and not message.error():
                try:
                    payload = json.loads(message.value())
                except (ValueError, TypeError):
                    skipped += 1
                    payload = None
                if payload is not None:
                    record = record_from_normalized(payload)
                    if record is None:
                        skipped += 1
                    else:
                        completed = buffers.add(record)
                        if completed is not None:
                            pending.append(encode(completed))
            elif message is not None and message.error():
                logger.warning("Consumer error", extra={"error": str(message.error())})

            if len(pending) >= settings.batch_size or (
                pending and now - last_flush >= settings.flush_interval_seconds
            ):
                flush()
                last_flush = now
                logger.info(
                    "Scorer progress",
                    extra={"scored": scored, "alerts": alerts, "skipped": skipped,
                           "tracked_hosts": buffers.tracked_hosts},
                )
    except Exception:
        logger.critical("Scorer failed", exc_info=True)
        return 1
    finally:
        try:
            flush()
        finally:
            consumer.close()
            if writer is not None:
                writer.close()
            logger.info("Scorer stopped",
                        extra={"scored": scored, "alerts": alerts, "skipped": skipped})

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
