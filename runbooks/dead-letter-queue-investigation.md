# Dead-Letter Queue Investigation

## Purpose

Determine how much data is being dead-lettered, where in the pipeline it is
being rejected, and whether it can be replayed. The pipeline has two distinct
dead-letter paths that must not be confused:

1. **Producer spool** — records the producer could not deliver to Kafka at all,
   written to `/var/spool/forensics/dlq.jsonl` inside the producer container
   (`make dlq`). SignalOps cannot see this path.
2. **Stream DLQ** — records Spark received but rejected at validation, written to
   the `logs.raw.dlq` topic. This is what SignalOps measures.

Rows that pass stream validation but fail the SQL normalisation transform are a
third failure mode, recorded in `evidence.raw_events.normalize_error`.

## Symptoms

- `dlq.records_in_window` above zero and rising.
- `dlq_spike` or `normalize_failures` incident candidates.
- Retained DLQ records (`dlq.retained_records`) growing steadily over days.

## Evidence to collect

1. `get_dlq_summary` for the window: DLQ count, raw count, ratio, reason sample.
2. `normalize_failures_in_window` and `recent_normalize_failures` from the same summary.
3. `get_pipeline_metrics` series `spark.dlq_rows_written` and `spark.raw_rows_processed`
   to locate the onset.
4. `make lag` output for consumer-group lag if the scorer is involved.

## Diagnostic steps

1. Establish the rate: compare `dlq.records_in_window` with
   `raw.records_in_window`. Both are derived from Kafka offsets over the same
   window and do not consume any messages.
2. Check whether the sampled reasons cover the whole window
   (`sample_covers_window`). If not, widen the sample or narrow the window.
3. Separate the paths: stream DLQ reasons are validation codes
   (see `schema-validation-errors.md`); normalisation failures carry PostgreSQL
   error text in `normalize_error`.
4. For normalisation failures, check whether a migration was skipped
   (`make migrate-status`) or a dimension constraint changed.
5. Confirm the producer spool is empty (`make dlq`) to rule out delivery failure.

## Expected observations

- A healthy pipeline with synthetic telemetry has a DLQ ratio of approximately zero.
- A validation incident shows DLQ count and ratio rising together, with
  normalised output falling by a similar amount.
- A normalisation incident shows a normal DLQ but rising `normalize_failures`.

## Possible causes

- Upstream schema change (see the schema validation runbook).
- Bad or test traffic injected onto `logs.raw`.
- Database migration drift causing the normalisation transform to fail.
- Malformed addresses or values that pass stream validation but violate a
  database constraint.

## Recommended next steps

- Fix the cause before replaying; replaying into the same defect re-rejects every record.
- Replay stream DLQ records by re-publishing their preserved `payload` field to
  `logs.raw` with a one-off consumer, after review. Spark's idempotent landing and
  the `(event_id, occurred_at)` key make replays safe against duplicates once normalised.
- Re-run normalisation with `make normalize` after fixing a transform defect.

## Escalation criteria

- DLQ retention approaching `KAFKA_TOPIC_RETENTION_MS` (default 7 days) with
  unreplayed records: data loss is imminent; escalate.
- Normalisation failures on more than 1% of landed rows.
- Any sign that DLQ volume is concentrated on one host under investigation.

## Limitations and safety

- Offset-derived counts assume a non-transactional producer (true for this
  pipeline); with transactions they would be an upper bound.
- The DLQ sample reads only the newest records per partition with an assigned
  consumer and never commits offsets; it does not affect other consumers.
- Never purge the DLQ topic as a "fix"; it destroys the only replayable copy.
