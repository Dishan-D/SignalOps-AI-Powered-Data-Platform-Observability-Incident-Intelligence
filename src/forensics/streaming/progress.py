"""Durable Structured Streaming progress, for the operational layer.

Spark hands a ``StreamingQueryProgress`` to in-process listeners after every
micro-batch and keeps nothing else: the UI's REST API has no Structured
Streaming endpoint. This module copies those reports into ``ops.stream_progress``
and ``ops.stream_queries`` (migration 0005) so that processing rates, Kafka lag
and query failures can be read back by something other than the driver.

Isolation rules, because this code runs inside the streaming driver:

* **Never raise into Spark.** Every listener callback swallows and logs its own
  errors. A broken observability path must not take down the pipeline it
  observes.
* **Never block Spark.** Callbacks only enqueue; a daemon thread does the
  Postgres I/O. The queue is bounded and drops the oldest report when full, so
  a database outage costs telemetry, not memory.
* **No pyspark import at module level.** The parsing logic is pure Python and is
  tested without a JVM; the listener subclass is built lazily by
  :func:`build_listener`.

Python 3.10-compatible: this module ships in the apache/spark image.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from forensics.common.logging import get_logger

logger = get_logger(__name__, component="stream-progress")

#: Reports buffered while the writer is behind or the database is down.
QUEUE_CAPACITY = 1_000

#: Progress rows older than this are pruned by the writer.
DEFAULT_RETENTION_HOURS = 72


def _parse_spark_time(value: Any) -> dt.datetime | None:
    """Parse Spark's ISO-8601 progress timestamps (``2026-10-23T10:00:00.123Z``)."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    # Spark reports NaN for rates over a zero-length interval.
    return None if number != number else number


@dataclass(frozen=True)
class ProgressRow:
    """One micro-batch, flattened for ``ops.stream_progress``."""

    query_name: str
    query_id: str
    run_id: str
    batch_id: int
    batch_timestamp: dt.datetime
    num_input_rows: int | None
    input_rows_per_second: float | None
    processed_rows_per_second: float | None
    trigger_execution_ms: int | None
    max_offsets_behind_latest: int | None
    watermark: dt.datetime | None
    sink_output_rows: int | None
    sources: list[dict[str, Any]] = field(default_factory=list)


def progress_row(progress: dict[str, Any]) -> ProgressRow | None:
    """Map Spark's progress JSON to a row, or ``None`` if it is unusable.

    Only fields Spark actually reported are kept; a missing value stays ``None``
    rather than becoming zero, so "Spark did not say" is distinguishable from
    "Spark said nothing happened".
    """
    batch_id = _as_int(progress.get("batchId"))
    timestamp = _parse_spark_time(progress.get("timestamp"))
    query_id = progress.get("id")
    run_id = progress.get("runId")
    if batch_id is None or timestamp is None or not query_id or not run_id:
        return None

    sources_out: list[dict[str, Any]] = []
    lag_values: list[int] = []
    for source in progress.get("sources") or []:
        if not isinstance(source, dict):
            continue
        metrics = source.get("metrics") or {}
        lag = _as_int(metrics.get("maxOffsetsBehindLatest"))
        if lag is not None:
            lag_values.append(lag)
        sources_out.append(
            {
                "description": str(source.get("description", ""))[:200],
                "num_input_rows": _as_int(source.get("numInputRows")),
                "end_offset": source.get("endOffset"),
                "latest_offset": source.get("latestOffset"),
                "max_offsets_behind_latest": lag,
            }
        )

    sink = progress.get("sink") or {}
    sink_rows = _as_int(sink.get("numOutputRows")) if isinstance(sink, dict) else None
    if sink_rows is not None and sink_rows < 0:
        sink_rows = None

    duration = progress.get("durationMs") or {}
    event_time = progress.get("eventTime") or {}

    return ProgressRow(
        query_name=str(progress.get("name") or query_id),
        query_id=str(query_id),
        run_id=str(run_id),
        batch_id=batch_id,
        batch_timestamp=timestamp,
        num_input_rows=_as_int(progress.get("numInputRows")),
        input_rows_per_second=_as_float(progress.get("inputRowsPerSecond")),
        processed_rows_per_second=_as_float(progress.get("processedRowsPerSecond")),
        trigger_execution_ms=_as_int(
            duration.get("triggerExecution") if isinstance(duration, dict) else None
        ),
        max_offsets_behind_latest=max(lag_values) if lag_values else None,
        watermark=_parse_spark_time(
            event_time.get("watermark") if isinstance(event_time, dict) else None
        ),
        sink_output_rows=sink_rows,
        sources=sources_out,
    )


@dataclass(frozen=True)
class LifecycleEvent:
    """A query state change for ``ops.stream_queries``."""

    query_name: str
    query_id: str
    run_id: str
    status: str  # active | idle | terminated
    at: dt.datetime
    batch_id: int | None = None
    exception: str | None = None
    started: bool = False


def _now() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)


# --------------------------------------------------------------------------- #
# Writer                                                                       #
# --------------------------------------------------------------------------- #

UPSERT_QUERY_SQL = """
INSERT INTO ops.stream_queries
    (query_name, query_id, run_id, status, started_at, last_event_at,
     last_progress_at, last_batch_id, exception)
VALUES (%(query_name)s, %(query_id)s, %(run_id)s, %(status)s, %(started_at)s,
        %(at)s, %(progress_at)s, %(batch_id)s, %(exception)s)
ON CONFLICT (query_name) DO UPDATE SET
    query_id         = EXCLUDED.query_id,
    run_id           = EXCLUDED.run_id,
    status           = EXCLUDED.status,
    started_at       = COALESCE(EXCLUDED.started_at,
                                CASE WHEN ops.stream_queries.run_id = EXCLUDED.run_id
                                     THEN ops.stream_queries.started_at END),
    last_event_at    = GREATEST(ops.stream_queries.last_event_at, EXCLUDED.last_event_at),
    last_progress_at = COALESCE(EXCLUDED.last_progress_at, ops.stream_queries.last_progress_at),
    last_batch_id    = COALESCE(EXCLUDED.last_batch_id, ops.stream_queries.last_batch_id),
    -- A restart clears the previous run's failure; a progress report does not.
    exception        = CASE WHEN EXCLUDED.status = 'terminated' THEN EXCLUDED.exception
                            WHEN EXCLUDED.started_at IS NOT NULL THEN NULL
                            ELSE ops.stream_queries.exception END
"""

INSERT_PROGRESS_SQL = """
INSERT INTO ops.stream_progress
    (query_name, query_id, run_id, batch_id, batch_timestamp, num_input_rows,
     input_rows_per_second, processed_rows_per_second, trigger_execution_ms,
     max_offsets_behind_latest, watermark, sink_output_rows, sources)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (run_id, batch_id) DO NOTHING
"""

PRUNE_SQL = "DELETE FROM ops.stream_progress WHERE batch_timestamp < now() - make_interval(hours => %s)"


class ProgressRecorder:
    """Buffers listener reports and writes them to Postgres off the Spark thread.

    ``connect`` returns a DB-API connection in autocommit mode; it is injected so
    tests can supply a fake and so the psycopg import stays lazy.
    """

    def __init__(
        self,
        connect: Callable[[], Any],
        *,
        capacity: int = QUEUE_CAPACITY,
        retention_hours: int = DEFAULT_RETENTION_HOURS,
        prune_every: int = 500,
    ) -> None:
        self._connect = connect
        self._queue: queue.Queue[ProgressRow | LifecycleEvent] = queue.Queue(maxsize=capacity)
        self._retention_hours = retention_hours
        self._prune_every = prune_every
        self._connection: Any = None
        self._written = 0
        self._dropped = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- producer side (Spark listener thread) ---------------------------------

    def submit(self, item: ProgressRow | LifecycleEvent) -> None:
        """Enqueue without blocking; drop the oldest item when full."""
        while True:
            try:
                self._queue.put_nowait(item)
                return
            except queue.Full:
                try:
                    self._queue.get_nowait()
                    self._dropped += 1
                except queue.Empty:
                    pass

    @property
    def dropped(self) -> int:
        return self._dropped

    # -- consumer side ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._run, name="stream-progress-writer", daemon=True
            )
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def _run(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            while not self._stop.is_set():
                try:
                    self.write(item)
                    backoff = 1.0
                    break
                except Exception:
                    logger.warning("Could not record stream progress; will retry", exc_info=True)
                    self._close()
                    self._stop.wait(backoff)
                    backoff = min(backoff * 2, 30.0)

    def _close(self) -> None:
        if self._connection is not None:
            with contextlib.suppress(Exception):  # best effort on a dead connection
                self._connection.close()
        self._connection = None

    def write(self, item: ProgressRow | LifecycleEvent) -> None:
        """Write one item synchronously (used by the thread and by tests)."""
        if self._connection is None:
            self._connection = self._connect()
        with self._connection.cursor() as cur:
            if isinstance(item, ProgressRow):
                cur.execute(
                    INSERT_PROGRESS_SQL,
                    (
                        item.query_name, item.query_id, item.run_id, item.batch_id,
                        item.batch_timestamp, item.num_input_rows,
                        item.input_rows_per_second, item.processed_rows_per_second,
                        item.trigger_execution_ms, item.max_offsets_behind_latest,
                        item.watermark, item.sink_output_rows, json.dumps(item.sources),
                    ),
                )
                cur.execute(
                    UPSERT_QUERY_SQL,
                    {
                        "query_name": item.query_name, "query_id": item.query_id,
                        "run_id": item.run_id, "status": "active", "started_at": None,
                        "at": item.batch_timestamp, "progress_at": item.batch_timestamp,
                        "batch_id": item.batch_id, "exception": None,
                    },
                )
                self._written += 1
                if self._prune_every and self._written % self._prune_every == 0:
                    cur.execute(PRUNE_SQL, (self._retention_hours,))
            else:
                cur.execute(
                    UPSERT_QUERY_SQL,
                    {
                        "query_name": item.query_name, "query_id": item.query_id,
                        "run_id": item.run_id, "status": item.status,
                        "started_at": item.at if item.started else None,
                        "at": item.at, "progress_at": None, "batch_id": item.batch_id,
                        "exception": (item.exception or None) and item.exception[:4000],
                    },
                )


# --------------------------------------------------------------------------- #
# Spark listener                                                               #
# --------------------------------------------------------------------------- #

def build_listener(recorder: ProgressRecorder, query_names: dict[str, str]) -> Any:
    """Return a ``StreamingQueryListener`` feeding ``recorder``.

    ``query_names`` maps query id -> name, populated by the caller as queries
    start; termination events carry only the id.
    """
    from pyspark.sql.streaming import StreamingQueryListener

    class _OpsListener(StreamingQueryListener):
        def onQueryStarted(self, event: Any) -> None:  # noqa: N802 - Spark API
            try:
                name = event.name or str(event.id)
                query_names[str(event.id)] = name
                recorder.submit(
                    LifecycleEvent(
                        query_name=name, query_id=str(event.id), run_id=str(event.runId),
                        status="active", at=_parse_spark_time(event.timestamp) or _now(),
                        started=True,
                    )
                )
            except Exception:  # must never propagate into Spark
                logger.warning("onQueryStarted handler failed", exc_info=True)

        def onQueryProgress(self, event: Any) -> None:  # noqa: N802 - Spark API
            try:
                row = progress_row(json.loads(event.progress.json))
                if row is not None:
                    recorder.submit(row)
            except Exception:
                logger.warning("onQueryProgress handler failed", exc_info=True)

        def onQueryIdle(self, event: Any) -> None:  # noqa: N802 - Spark API
            try:
                query_id = str(event.id)
                recorder.submit(
                    LifecycleEvent(
                        query_name=query_names.get(query_id, query_id), query_id=query_id,
                        run_id=str(event.runId), status="idle",
                        at=_parse_spark_time(event.timestamp) or _now(),
                    )
                )
            except Exception:
                logger.warning("onQueryIdle handler failed", exc_info=True)

        def onQueryTerminated(self, event: Any) -> None:  # noqa: N802 - Spark API
            try:
                query_id = str(event.id)
                recorder.submit(
                    LifecycleEvent(
                        query_name=query_names.get(query_id, query_id), query_id=query_id,
                        run_id=str(event.runId), status="terminated", at=_now(),
                        exception=event.exception,
                    )
                )
            except Exception:
                logger.warning("onQueryTerminated handler failed", exc_info=True)

    return _OpsListener()


def recorder_from_dsn(dsn: str) -> ProgressRecorder:
    """A recorder that connects with psycopg (imported lazily)."""

    def _connect() -> Any:
        import psycopg

        return psycopg.connect(dsn, autocommit=True, connect_timeout=5)

    return ProgressRecorder(_connect)


def drain(recorder: ProgressRecorder, timeout: float = 5.0) -> None:
    """Give the writer a moment to flush queued reports at shutdown."""
    deadline = time.monotonic() + timeout
    while not recorder._queue.empty() and time.monotonic() < deadline:
        time.sleep(0.1)
