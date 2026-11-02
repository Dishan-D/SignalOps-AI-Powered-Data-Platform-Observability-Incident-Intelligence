"""Pipeline metrics from Kafka offsets, Spark progress and Postgres.

Every metric names its source and, where it is windowed, the window. Stage
counts are taken over the same wall-clock window but by *different clocks*
(Kafka record timestamps vs Postgres insert time), and a record's stages fall
in different windows near the edges — see :data:`STAGE_NOTE`. The service
reports them side by side; it never subtracts one from another.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from signalops.config import Settings
from signalops.models import (
    Metric,
    PipelineMetrics,
    Series,
    StreamQueryState,
    TimePoint,
    ValueState,
    utcnow,
)
from signalops.services.common import (
    clamp_window,
    kafka_records_since,
    kafka_retained,
    measure,
    seconds_since,
    state_for,
)
from signalops.sources.errors import DataSourceError
from signalops.sources.kafka import KafkaInspector
from signalops.sources.postgres import Database

STAGE_NOTE = (
    "Stage counts share a window but not a clock: Kafka counts use record timestamps, "
    "Postgres counts use insert time. Records in flight at the window edges are counted "
    "by one stage and not yet by the next, so stage differences are not loss."
)

LANDING_LATENCY_NOTE = (
    "Kafka record timestamp (producer CreateTime) -> row inserted into evidence.raw_events. "
    "Covers Spark trigger wait, processing and the JDBC write; excludes normalisation and sealing."
)

NORMALIZE_LATENCY_NOTE = "Row landed in evidence.raw_events -> normalised into evidence.events."

# --------------------------------------------------------------------------- #
# SQL                                                                          #
# --------------------------------------------------------------------------- #

LANDED_IN_WINDOW_SQL = """
SELECT count(*) AS n FROM evidence.raw_events
 WHERE landed_at >= now() - make_interval(mins => %(window)s)
"""

PENDING_SQL = """
SELECT count(*) AS pending, min(landed_at) AS oldest
  FROM evidence.raw_events WHERE normalized_at IS NULL
"""

NORMALIZE_FAILURES_SQL = """
SELECT count(*) AS n FROM evidence.raw_events
 WHERE normalize_error IS NOT NULL
   AND landed_at >= now() - make_interval(mins => %(window)s)
"""

LANDING_LATENCY_SQL = """
SELECT count(*) AS n,
       percentile_cont(0.5)  WITHIN GROUP (ORDER BY extract(epoch FROM landed_at - ingested_at)) AS p50,
       percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM landed_at - ingested_at)) AS p95
  FROM evidence.raw_events
 WHERE landed_at >= now() - make_interval(mins => %(window)s)
   AND ingested_at IS NOT NULL
"""

NORMALIZE_LATENCY_SQL = """
SELECT count(*) AS n,
       percentile_cont(0.5)  WITHIN GROUP (ORDER BY extract(epoch FROM normalized_at - landed_at)) AS p50,
       percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM normalized_at - landed_at)) AS p95
  FROM evidence.raw_events
 WHERE normalized_at >= now() - make_interval(mins => %(window)s)
   AND normalize_error IS NULL
"""

LANDED_SERIES_SQL = """
SELECT date_bin(make_interval(mins => %(bucket)s), landed_at, TIMESTAMPTZ '2000-01-01') AS bucket,
       count(*) AS landed,
       count(*) FILTER (WHERE normalize_error IS NOT NULL) AS failed
  FROM evidence.raw_events
 WHERE landed_at >= now() - make_interval(mins => %(window)s)
 GROUP BY 1 ORDER BY 1
"""

STREAM_QUERIES_SQL = """
SELECT query_name, status, last_event_at, last_progress_at, last_batch_id, exception
  FROM ops.stream_queries
"""

STREAM_WINDOW_SQL = """
SELECT query_name,
       count(*)                      AS batches,
       sum(num_input_rows)           AS input_rows,
       sum(sink_output_rows)         AS output_rows,
       count(sink_output_rows)       AS batches_reporting_output,
       max(batch_timestamp)          AS last_batch
  FROM ops.stream_progress
 WHERE batch_timestamp >= now() - make_interval(mins => %(window)s)
 GROUP BY query_name
"""

STREAM_LATEST_SQL = """
SELECT DISTINCT ON (query_name)
       query_name, batch_timestamp, processed_rows_per_second, max_offsets_behind_latest,
       trigger_execution_ms
  FROM ops.stream_progress
 WHERE batch_timestamp >= now() - make_interval(mins => %(window)s)
 ORDER BY query_name, batch_timestamp DESC
"""

STREAM_SERIES_SQL = """
SELECT date_bin(make_interval(mins => %(bucket)s), batch_timestamp, TIMESTAMPTZ '2000-01-01') AS bucket,
       query_name,
       sum(num_input_rows)            AS input_rows,
       sum(sink_output_rows)          AS output_rows,
       max(max_offsets_behind_latest) AS lag
  FROM ops.stream_progress
 WHERE batch_timestamp >= now() - make_interval(mins => %(window)s)
   AND query_name = ANY(%(queries)s)
 GROUP BY 1, 2 ORDER BY 1
"""

DETECTION_WINDOW_SQL = """
SELECT count(*) AS scored, count(*) FILTER (WHERE flagged) AS flagged, max(scored_at) AS last_scored
  FROM analytics.detections
 WHERE scored_at >= now() - make_interval(mins => %(window)s)
"""

DETECTION_SERIES_SQL = """
SELECT date_bin(make_interval(mins => %(bucket)s), scored_at, TIMESTAMPTZ '2000-01-01') AS bucket,
       count(*) AS scored, count(*) FILTER (WHERE flagged) AS flagged
  FROM analytics.detections
 WHERE scored_at >= now() - make_interval(mins => %(window)s)
 GROUP BY 1 ORDER BY 1
"""


def bucket_minutes_for(window_minutes: int) -> int:
    """About 30-120 points per chart regardless of window."""
    for bucket in (1, 5, 15, 60, 240):
        if window_minutes / bucket <= 120:
            return bucket
    return 1440


def _bucket_axis(now: dt.datetime, window: int, bucket: int) -> list[dt.datetime]:
    origin = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
    step = dt.timedelta(minutes=bucket)
    start = now - dt.timedelta(minutes=window)
    first = origin + ((start - origin) // step) * step
    axis = []
    t = first
    while t <= now:
        axis.append(t)
        t += step
    return axis


def _count_series(name: str, source: str, rows: list[dict[str, Any]], column: str,
                  axis: list[dt.datetime], unit: str = "records") -> Series:
    """Zero-fill a count series. Valid only because the query *succeeded*: a bucket
    with no rows genuinely had zero of them."""
    by_bucket = {_aware(r["bucket"]): float(r[column] or 0) for r in rows}
    return Series(name=name, unit=unit, source=source, state=ValueState.ok,
                  points=[TimePoint(bucket=b, value=by_bucket.get(b, 0.0)) for b in axis])


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _failed_series(name: str, source: str, exc: DataSourceError, unit: str = "records") -> Series:
    return Series(name=name, unit=unit, source=source, state=state_for(exc), detail=exc.message)


class MetricsService:
    def __init__(self, db: Database, kafka: KafkaInspector | None, settings: Settings) -> None:
        self._db = db
        self._kafka = kafka
        self._settings = settings

    # -- stream queries --------------------------------------------------------

    def stream_queries(self, now: dt.datetime | None = None) -> list[StreamQueryState]:
        """State of every expected query; raises DataSourceError if unreadable."""
        now = now or utcnow()
        rows = {r["query_name"]: r for r in self._db.fetch_all(STREAM_QUERIES_SQL)}
        stale_after = self._settings.thresholds.stream_stale_seconds
        out = []
        names = list(self._settings.stream_queries) + sorted(
            set(rows) - set(self._settings.stream_queries))
        for name in names:
            row = rows.get(name)
            if row is None:
                out.append(StreamQueryState(query_name=name, status="missing"))
                continue
            age = seconds_since(row["last_event_at"], now)
            out.append(StreamQueryState(
                query_name=name, status=row["status"], last_event_at=row["last_event_at"],
                last_progress_at=row["last_progress_at"], last_batch_id=row["last_batch_id"],
                seconds_since_event=age,
                stale=None if age is None else (row["status"] != "terminated" and age > stale_after),
                exception=(row["exception"] or None) and row["exception"][:1000],
            ))
        return out

    # -- metrics ---------------------------------------------------------------

    def collect(self, window_minutes: int = 60) -> PipelineMetrics:
        window = clamp_window(window_minutes)
        bucket = bucket_minutes_for(window)
        now = utcnow()
        since = now - dt.timedelta(minutes=window)
        params = {"window": window, "bucket": bucket}
        metrics: list[Metric] = []
        series: list[Series] = []
        notes = [STAGE_NOTE]

        # Kafka -----------------------------------------------------------------
        kafka = self._kafka
        if kafka is None:
            for topic in (self._settings.raw_topic, self._settings.dlq_topic):
                metrics.append(Metric.missing(
                    f"kafka.{topic}.records_in_window", ValueState.unavailable,
                    source="kafka", detail="Kafka inspection not configured",
                    window_minutes=window))
        else:
            inspector = kafka
            for topic in (self._settings.raw_topic, self._settings.dlq_topic):
                def in_window(t: str = topic) -> int:
                    return kafka_records_since(inspector, t, since)

                def retained(t: str = topic) -> int:
                    return kafka_retained(inspector, t)

                metrics.append(measure(f"kafka.{topic}.records_in_window", f"kafka offsets ({topic})",
                                       in_window, unit="records", window_minutes=window))
                metrics.append(measure(f"kafka.{topic}.retained_records", f"kafka watermarks ({topic})",
                                       retained, unit="records"))

        # Postgres landing / normalisation -------------------------------------
        metrics.append(measure(
            "postgres.raw_events.landed_in_window", "evidence.raw_events",
            lambda: self._db.fetch_one(LANDED_IN_WINDOW_SQL, params)["n"],  # type: ignore[index]
            unit="records", window_minutes=window))
        metrics.extend(self._pending_metrics(now))
        metrics.append(measure(
            "postgres.normalize_failures_in_window", "evidence.raw_events.normalize_error",
            lambda: self._db.fetch_one(NORMALIZE_FAILURES_SQL, params)["n"],  # type: ignore[index]
            unit="records", window_minutes=window))
        metrics.extend(self._latency_metrics(
            "latency.landing", LANDING_LATENCY_SQL, params, window, LANDING_LATENCY_NOTE))
        metrics.extend(self._latency_metrics(
            "latency.normalize", NORMALIZE_LATENCY_SQL, params, window, NORMALIZE_LATENCY_NOTE))

        try:
            rows = self._db.fetch_all(LANDED_SERIES_SQL, params)
            axis = _bucket_axis(now, window, bucket)
            series.append(_count_series("postgres.landed", "evidence.raw_events", rows, "landed", axis))
            series.append(_count_series("postgres.normalize_failures", "evidence.raw_events",
                                        rows, "failed", axis))
        except DataSourceError as exc:
            series.append(_failed_series("postgres.landed", "evidence.raw_events", exc))
            series.append(_failed_series("postgres.normalize_failures", "evidence.raw_events", exc))

        # Spark -----------------------------------------------------------------
        try:
            queries = self.stream_queries(now)
        except DataSourceError as exc:
            queries = []
            notes.append(f"Spark query state unavailable: {exc.message}")
        metrics.extend(self._spark_metrics(params, window))
        series.extend(self._spark_series(params, now, window, bucket))

        # Detections ------------------------------------------------------------
        metrics.extend(self._detection_metrics(params, window, now))
        try:
            rows = self._db.fetch_all(DETECTION_SERIES_SQL, params)
            axis = _bucket_axis(now, window, bucket)
            series.append(_count_series("detections.scored", "analytics.detections", rows,
                                        "scored", axis, unit="windows"))
            series.append(_count_series("detections.flagged", "analytics.detections", rows,
                                        "flagged", axis, unit="windows"))
        except DataSourceError as exc:
            series.append(_failed_series("detections.scored", "analytics.detections", exc, "windows"))
            series.append(_failed_series("detections.flagged", "analytics.detections", exc, "windows"))

        return PipelineMetrics(generated_at=now, window_minutes=window, bucket_minutes=bucket,
                               metrics=metrics, series=series, stream_queries=queries, notes=notes)

    def _pending_metrics(self, now: dt.datetime) -> list[Metric]:
        try:
            row = self._db.fetch_one(PENDING_SQL) or {}
        except DataSourceError as exc:
            return [Metric.missing(n, state_for(exc), source="evidence.raw_events", detail=exc.message)
                    for n in ("postgres.normalize_pending", "postgres.normalize_oldest_pending_age")]
        out = [Metric.ok("postgres.normalize_pending", float(row.get("pending") or 0),
                         source="evidence.raw_events", unit="records")]
        age = seconds_since(row.get("oldest"), now)
        if age is None:
            out.append(Metric.missing("postgres.normalize_oldest_pending_age", ValueState.unknown,
                                      source="evidence.raw_events", unit="seconds",
                                      detail="no rows are waiting for normalisation"))
        else:
            out.append(Metric.ok("postgres.normalize_oldest_pending_age", age,
                                 source="evidence.raw_events", unit="seconds"))
        return out

    def _latency_metrics(self, prefix: str, sql: str, params: dict[str, Any], window: int,
                         note: str) -> list[Metric]:
        names = (f"{prefix}.p50", f"{prefix}.p95")
        try:
            row = self._db.fetch_one(sql, params) or {}
        except DataSourceError as exc:
            return [Metric.missing(n, state_for(exc), source="evidence.raw_events",
                                   detail=exc.message, unit="seconds", window_minutes=window)
                    for n in names]
        if not row.get("n"):
            return [Metric.missing(n, ValueState.unknown, source="evidence.raw_events",
                                   detail="no records in window", unit="seconds",
                                   window_minutes=window) for n in names]
        sample = int(row["n"])
        return [
            Metric.ok(names[0], float(row["p50"]), source="evidence.raw_events", unit="seconds",
                      window_minutes=window, detail=f"{note} n={sample}"),
            Metric.ok(names[1], float(row["p95"]), source="evidence.raw_events", unit="seconds",
                      window_minutes=window, detail=f"{note} n={sample}"),
        ]

    def _spark_metrics(self, params: dict[str, Any], window: int) -> list[Metric]:
        source = "ops.stream_progress"
        try:
            totals = {r["query_name"]: r for r in self._db.fetch_all(STREAM_WINDOW_SQL, params)}
            latest = {r["query_name"]: r for r in self._db.fetch_all(STREAM_LATEST_SQL, params)}
        except DataSourceError as exc:
            state = state_for(exc)
            return [Metric.missing(n, state, source=source, detail=exc.message, window_minutes=window)
                    for n in ("spark.raw_rows_processed", "spark.dlq_rows_written",
                              "spark.normalized_rows_written", "spark.max_offsets_behind_latest")]

        def total(query: str, column: str, name: str, unit: str = "records") -> Metric:
            row = totals.get(query)
            if row is None:
                return Metric.missing(name, ValueState.unknown, source=source, window_minutes=window,
                                      unit=unit, detail=f"no progress from query {query!r} in window")
            if column == "output_rows" and not row["batches_reporting_output"]:
                return Metric.missing(name, ValueState.unknown, source=source, window_minutes=window,
                                      unit=unit, detail=f"sink of {query!r} does not report output rows")
            return Metric.ok(name, float(row[column] or 0), source=f"{source} ({query})", unit=unit,
                             window_minutes=window, detail=f"{row['batches']} micro-batches")

        out = [
            # Every query reads logs.raw independently; the normalised query's input
            # is therefore the number of raw records Spark consumed.
            total("normalized-events", "input_rows", "spark.raw_rows_processed"),
            total("dead-letters", "output_rows", "spark.dlq_rows_written"),
            total("normalized-events", "output_rows", "spark.normalized_rows_written"),
        ]
        lags = [r["max_offsets_behind_latest"] for r in latest.values()
                if r["max_offsets_behind_latest"] is not None]
        if lags:
            out.append(Metric.ok("spark.max_offsets_behind_latest", float(max(lags)),
                                 source=source, unit="offsets",
                                 detail="max over queries of Spark's maxOffsetsBehindLatest in the latest batch"))
        else:
            out.append(Metric.missing("spark.max_offsets_behind_latest", ValueState.unknown,
                                      source=source, unit="offsets",
                                      detail="Spark reported no offset lag in the window"))
        rates = [r["processed_rows_per_second"] for q, r in latest.items()
                 if q == "normalized-events" and r["processed_rows_per_second"] is not None]
        if rates:
            out.append(Metric.ok("spark.processed_rows_per_second", float(rates[0]),
                                 source=f"{source} (normalized-events)", unit="rows/s",
                                 detail="latest micro-batch"))
        else:
            out.append(Metric.missing("spark.processed_rows_per_second", ValueState.unknown,
                                      source=source, unit="rows/s",
                                      detail="no recent normalized-events batch"))
        return out

    def _spark_series(self, params: dict[str, Any], now: dt.datetime, window: int,
                      bucket: int) -> list[Series]:
        source = "ops.stream_progress"
        names = ("spark.raw_rows_processed", "spark.dlq_rows_written", "spark.offsets_behind_latest")
        try:
            rows = self._db.fetch_all(
                STREAM_SERIES_SQL,
                {**params, "queries": ["normalized-events", "dead-letters"]},
            )
        except DataSourceError as exc:
            return [_failed_series(n, source, exc) for n in names]
        axis = _bucket_axis(now, window, bucket)
        normalized = [r for r in rows if r["query_name"] == "normalized-events"]
        dead = [r for r in rows if r["query_name"] == "dead-letters"]
        out = [_count_series(names[0], f"{source} (normalized-events)", normalized, "input_rows", axis)]
        if any(r["output_rows"] is not None for r in dead) or not dead:
            out.append(_count_series(names[1], f"{source} (dead-letters)", dead, "output_rows", axis))
        else:
            out.append(Series(name=names[1], unit="records", source=source, state=ValueState.unknown,
                              detail="dead-letters sink does not report output rows"))
        # Lag is a gauge: no zero-fill, a missing bucket is "no report", not "no lag".
        lag_by_bucket: dict[dt.datetime, float] = {}
        for r in rows:
            if r["lag"] is not None:
                b = _aware(r["bucket"])
                lag_by_bucket[b] = max(lag_by_bucket.get(b, 0.0), float(r["lag"]))
        out.append(Series(
            name=names[2], unit="offsets", source=source,
            state=ValueState.ok if lag_by_bucket else ValueState.unknown,
            points=[TimePoint(bucket=b, value=v) for b, v in sorted(lag_by_bucket.items())],
            detail=None if lag_by_bucket else "Spark reported no offset lag in the window",
        ))
        return out

    def _detection_metrics(self, params: dict[str, Any], window: int,
                           now: dt.datetime) -> list[Metric]:
        source = "analytics.detections"
        names = ("detections.scored_windows", "detections.flagged_windows",
                 "detections.seconds_since_last_score")
        try:
            row = self._db.fetch_one(DETECTION_WINDOW_SQL, params) or {}
        except DataSourceError as exc:
            return [Metric.missing(n, state_for(exc), source=source, detail=exc.message,
                                   window_minutes=window) for n in names]
        out = [
            Metric.ok(names[0], float(row.get("scored") or 0), source=source, unit="windows",
                      window_minutes=window),
            Metric.ok(names[1], float(row.get("flagged") or 0), source=source, unit="windows",
                      window_minutes=window),
        ]
        age = seconds_since(row.get("last_scored"), now)
        out.append(
            Metric.ok(names[2], age, source=source, unit="seconds")
            if age is not None else
            Metric.missing(names[2], ValueState.unknown, source=source, unit="seconds",
                           detail="no windows scored in the window (is the scorer deployed?)")
        )
        return out
