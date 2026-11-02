# Spark Processing Delays

## Purpose

Diagnose Spark Structured Streaming queries that are slow, stalled, or have
terminated. The job runs five independent queries over `logs.raw`
(`normalized-events`, `dead-letters`, `host-activity-features`,
`peer-connection-features`, `evidence-store`), each with its own checkpoint.
Progress for each is persisted by the driver-side listener to
`ops.stream_progress` and `ops.stream_queries`.

## Symptoms

- `spark` component `degraded` (stale or stopped queries) or `unhealthy`
  (a query terminated with an exception).
- `stream_stalled` or `stream_query_failed` incident candidates.
- `spark.max_offsets_behind_latest` increasing over successive batches.
- `latency.landing.p95` rising.

## Evidence to collect

1. `get_pipeline_health` — per-query status and seconds since the last event.
2. `get_pipeline_metrics` — `spark.raw_rows_processed`, `spark.processed_rows_per_second`,
   `spark.max_offsets_behind_latest`, landing latency percentiles.
3. Spark driver logs: `make spark-logs`; the Spark UI on port 4040 for live batch durations.
4. The `exception` text recorded for any terminated query.

## Diagnostic steps

1. **Terminated with an exception?** Read the recorded exception. The job exits
   when *any* query fails (`awaitAnyTermination`), so one failing sink stops all
   five. Common exceptions: JDBC connection refused (Postgres down), checkpoint
   incompatibility after a code change, Kafka offsets out of range.
2. **Stale but not terminated?** Compare `last_event_at` across queries. All stale
   at once means the driver is hung or the listener cannot write (check
   `SPARK_PROGRESS_DSN` and Postgres health). One stale query means that query's
   sink is blocked.
3. **Running but falling behind?** Compare processed rows per second with the
   input rate. Lag that grows every batch means the job cannot keep up; check
   `SPARK_MAX_OFFSETS_PER_TRIGGER`, trigger interval, and JDBC write time.
4. **Landing latency high but lag low?** Time is being spent between Kafka and
   Postgres (trigger wait plus the JDBC write), not in consumption.

## Expected observations

- Healthy: every query reports within the stale threshold (default 180 s), lag
  close to zero between batches, landing p95 a small multiple of the trigger interval.
- Postgres outage: `evidence-store` terminates with a JDBC exception, the job exits,
  and all queries stop reporting.
- Under-provisioned: lag and landing latency rise steadily without errors.

## Possible causes

- Downstream sink unavailable (Postgres for `evidence-store`, Kafka for the others).
- Incompatible checkpoint after a schema or query change.
- Micro-batch size or trigger interval mis-sized for the input rate.
- Driver memory pressure from stateful windowed aggregations (watermark too long).

## Recommended next steps

- Restore the failing dependency, then restart the Spark container; checkpoints
  resume from the last committed offsets.
- For an incompatible checkpoint, do not delete it during an incident; record the
  failure and escalate, since deleting it replays or skips data.
- For sustained lag, raise `SPARK_MAX_OFFSETS_PER_TRIGGER` or resources and watch
  whether lag stops growing within two windows.

## Escalation criteria

- Any query terminated with an exception for more than 10 minutes.
- Lag growing for more than 30 minutes.
- A fix that requires deleting or resetting checkpoints.

## Limitations and safety

- Spark telemetry exists only while the listener can write to Postgres; if
  Postgres is down, Spark health becomes `unknown`, not healthy.
- `maxOffsetsBehindLatest` is Spark's own measure at batch end; between batches
  actual lag can be higher.
- Never delete `spark-checkpoints` as a troubleshooting step.
