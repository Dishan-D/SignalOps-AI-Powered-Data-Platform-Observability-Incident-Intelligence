"""Dead-letter and validation-failure summaries.

Two failure paths exist and both are reported, separately:

1. **Stream validation** — Spark's ``_validation_error`` rejects a record and
   ``to_dlq_records`` writes it to ``logs.raw.dlq`` with the reason in
   ``error``. Counted from offsets; reasons come from a bounded tail sample.
2. **Normalisation** — rows that passed stream validation but failed the SQL
   transform keep ``normalize_error`` in ``evidence.raw_events``.

Payload previews are sanitised: the raw event carries synthetic ground-truth
labels (``labels.ground_truth``) that must never reach an operator view or the
investigation agent, so they are removed before truncation.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections import Counter
from typing import Any

from signalops.config import Settings
from signalops.models import (
    DlqRecord,
    DlqSummary,
    Metric,
    NormalizeFailure,
    ValueState,
    utcnow,
)
from signalops.services.common import (
    clamp_window,
    kafka_records_since,
    kafka_retained,
    measure,
)
from signalops.sources.errors import DataSourceError
from signalops.sources.kafka import KafkaInspector
from signalops.sources.postgres import Database

PREVIEW_CHARS = 240
MAX_SAMPLE_PER_PARTITION = 200

#: Keys stripped from any JSON payload before it is shown.
_LABEL_KEYS = ("labels", "ground_truth", "eval_is_anomaly", "eval_scenario",
               "eval_campaign_id", "eval_step")
_LABEL_TEXT = re.compile(r'"(labels|ground_truth)"\s*:\s*\{[^{}]*(\{[^{}]*\}[^{}]*)*\}', re.S)

RECENT_NORMALIZE_FAILURES_SQL = """
SELECT raw_id, landed_at, normalize_error AS error, host_name
  FROM evidence.raw_events
 WHERE normalize_error IS NOT NULL
   AND landed_at >= now() - make_interval(mins => %(window)s)
 ORDER BY landed_at DESC
 LIMIT %(limit)s
"""

NORMALIZE_FAILURE_COUNT_SQL = """
SELECT count(*) AS n FROM evidence.raw_events
 WHERE normalize_error IS NOT NULL
   AND landed_at >= now() - make_interval(mins => %(window)s)
"""


def _strip_labels(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_labels(v) for k, v in value.items() if k not in _LABEL_KEYS}
    if isinstance(value, list):
        return [_strip_labels(v) for v in value]
    return value


def sanitize_payload(payload: str | None, limit: int = PREVIEW_CHARS) -> str | None:
    """Remove ground-truth labels from a raw payload and truncate it."""
    if payload is None:
        return None
    try:
        text = json.dumps(_strip_labels(json.loads(payload)), separators=(",", ":"))
    except (ValueError, TypeError):
        # Malformed JSON (the usual reason it is in the DLQ): best-effort textual
        # redaction, then truncate.
        text = _LABEL_TEXT.sub('"labels":"[redacted]"', payload)
        if "ground_truth" in text:
            text = text[: text.find("ground_truth")] + "[redacted]"
    return text if len(text) <= limit else text[:limit] + "…"


def parse_dlq_value(value: bytes | None) -> dict[str, Any]:
    """Decode a DLQ record written by ``forensics.streaming.normalize.to_dlq_records``."""
    if value is None:
        return {}
    try:
        decoded = json.loads(value.decode("utf-8", errors="replace"))
    except ValueError:
        return {"error": "unparseable_dlq_record"}
    return decoded if isinstance(decoded, dict) else {"error": "unparseable_dlq_record"}


class DlqService:
    def __init__(self, db: Database, kafka: KafkaInspector | None, settings: Settings) -> None:
        self._db = db
        self._kafka = kafka
        self._settings = settings

    def summary(self, window_minutes: int = 60, sample_per_partition: int = 50) -> DlqSummary:
        window = clamp_window(window_minutes)
        sample_per_partition = max(1, min(sample_per_partition, MAX_SAMPLE_PER_PARTITION))
        now = utcnow()
        since = now - dt.timedelta(minutes=window)
        topic = self._settings.dlq_topic
        raw_topic = self._settings.raw_topic
        notes: list[str] = []
        kafka = self._kafka

        if kafka is None:
            missing = ValueState.unavailable
            detail = "Kafka inspection not configured"
            retained = Metric.missing("dlq.retained_records", missing, source="kafka", detail=detail)
            in_window = Metric.missing("dlq.records_in_window", missing, source="kafka",
                                       detail=detail, window_minutes=window)
            raw_in_window = Metric.missing("raw.records_in_window", missing, source="kafka",
                                           detail=detail, window_minutes=window)
        else:
            retained = measure("dlq.retained_records", f"kafka watermarks ({topic})",
                               lambda: kafka_retained(kafka, topic), unit="records")
            in_window = measure("dlq.records_in_window", f"kafka offsets ({topic})",
                                lambda: kafka_records_since(kafka, topic, since),
                                unit="records", window_minutes=window)
            raw_in_window = measure("raw.records_in_window", f"kafka offsets ({raw_topic})",
                                    lambda: kafka_records_since(kafka, raw_topic, since),
                                    unit="records", window_minutes=window)

        ratio = self._ratio(in_window, raw_in_window, window)

        samples: list[DlqRecord] = []
        covers: bool | None = None
        if kafka is not None and retained.state is ValueState.ok and (retained.value or 0) > 0:
            try:
                records = kafka.tail(topic, sample_per_partition,
                                     timeout_seconds=self._settings.kafka_timeout_seconds + 2)
                samples = sorted((self._to_record(r) for r in records),
                                 key=lambda r: (r.timestamp or now), reverse=True)
                in_window_samples = [s for s in samples if s.timestamp and s.timestamp >= since]
                if in_window.state is ValueState.ok:
                    covers = len(in_window_samples) >= int(in_window.value or 0)
                if covers is False:
                    notes.append(
                        f"Reason counts come from the newest {len(in_window_samples)} of "
                        f"{int(in_window.value or 0)} DLQ records in the window; treat them as a sample."
                    )
            except DataSourceError as exc:
                notes.append(f"DLQ sample unavailable: {exc.message}")
        counts = Counter(s.error or "unknown" for s in samples
                         if s.timestamp is None or s.timestamp >= since)

        failures: list[NormalizeFailure] = []
        params = {"window": window, "limit": 20}
        failure_count = measure(
            "normalize.failures_in_window", "evidence.raw_events.normalize_error",
            lambda: (self._db.fetch_one(NORMALIZE_FAILURE_COUNT_SQL, params) or {}).get("n"),
            unit="records", window_minutes=window)
        if failure_count.state is ValueState.ok and failure_count.value:
            try:
                failures = [NormalizeFailure(**r)
                            for r in self._db.fetch_all(RECENT_NORMALIZE_FAILURES_SQL, params)]
            except DataSourceError as exc:
                notes.append(f"normalisation failure detail unavailable: {exc.message}")

        return DlqSummary(
            generated_at=now, topic=topic, window_minutes=window,
            retained_records=retained, records_in_window=in_window,
            raw_records_in_window=raw_in_window, dlq_ratio=ratio,
            sample_size=len(samples), sample_error_counts=dict(counts.most_common()),
            sample_covers_window=covers, samples=samples[:50],
            normalize_failures_in_window=failure_count,
            recent_normalize_failures=failures, notes=notes,
        )

    @staticmethod
    def _ratio(dlq: Metric, raw: Metric, window: int) -> Metric:
        source = "kafka offsets (dlq / raw)"
        if dlq.state is not ValueState.ok or raw.state is not ValueState.ok:
            worst = dlq if dlq.state is not ValueState.ok else raw
            return Metric.missing("dlq.ratio", worst.state, source=source, window_minutes=window,
                                  detail=f"inputs unavailable: {worst.detail}")
        if not raw.value:
            return Metric.missing("dlq.ratio", ValueState.unknown, source=source,
                                  window_minutes=window, detail="no raw records in window")
        return Metric.ok("dlq.ratio", (dlq.value or 0) / raw.value, source=source,
                         window_minutes=window, unit="fraction",
                         detail="DLQ records / raw records appended in the same window")

    @staticmethod
    def _to_record(record: Any) -> DlqRecord:
        body = parse_dlq_value(record.value)
        ts = (dt.datetime.fromtimestamp(record.timestamp_ms / 1000, tz=dt.timezone.utc)
              if record.timestamp_ms else None)
        payload = body.get("payload")
        return DlqRecord(
            partition=record.partition, offset=record.offset, timestamp=ts,
            error=str(body.get("error")) if body.get("error") is not None else None,
            source_partition=body.get("source_partition"),
            source_offset=body.get("source_offset"),
            rejected_at=str(body.get("rejected_at")) if body.get("rejected_at") else None,
            payload_preview=sanitize_payload(payload if isinstance(payload, str) else None),
        )


__all__ = ["DlqService", "parse_dlq_value", "sanitize_payload"]
