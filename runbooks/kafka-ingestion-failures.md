# Kafka Ingestion Failures

## Purpose

Diagnose problems getting telemetry into and through the KRaft-mode Kafka
broker: broker unavailability, missing topics, producers that stop publishing,
and consumers that fall behind.

## Symptoms

- `kafka` component `unavailable` or `degraded` on `/api/ops/health`.
- `kafka.logs.raw.records_in_window` at zero while producers should be running.
- `spark.max_offsets_behind_latest` growing across consecutive batches.
- Producer logs showing delivery failures or records spooled to the local DLQ.

## Evidence to collect

1. `get_pipeline_health` — Kafka component detail and the list of present topics.
2. `get_pipeline_metrics` — raw records in window, retained records per topic,
   Spark offset lag.
3. Producer logs: `make producer-logs` (delivery reports, `spooled` counters).
4. Topic list: `make topics`; consumer lag: `make lag`.

## Diagnostic steps

1. **Is the broker reachable?** If health reports `unavailable`, check
   `make ps` and `docker compose logs kafka`. The broker advertises `kafka:9092`
   inside Compose and `localhost:29092` to the host; a client on the wrong
   listener connects and then fails on metadata.
2. **Do the topics exist?** Auto-creation is disabled. A `degraded` status listing
   missing topics means `kafka-init` did not complete; re-run
   `docker compose up kafka-init`.
3. **Is anything being produced?** If raw records in window is zero, the producer
   is stopped or failing. Check its logs for delivery errors and whether
   `PRODUCER_MAX_EVENTS` was reached (a bounded run exits cleanly).
4. **Is the consumer keeping up?** If raw input is non-zero but Spark lag grows,
   go to `spark-processing-delays.md`.

## Expected observations

- Healthy: broker reachable, all six topics present, raw input roughly equal to
  `PRODUCER_EVENTS_PER_SECOND × window`, Spark lag small and stable.
- Producer down: raw input zero, retained records flat, broker healthy.
- Broker down: health `unavailable`, every Kafka-derived metric `unavailable`
  rather than zero.

## Possible causes

- Broker container stopped, out of disk, or restarting.
- Topic creation step skipped after a volume reset.
- Producer stopped, crashed, or reached its configured event limit.
- Listener misconfiguration (internal vs external address).
- Retention shorter than a consumer outage, so offsets were deleted before
  processing.

## Recommended next steps

- Restore the broker first; nothing downstream can recover without it.
- Recreate missing topics with `scripts/create-topics.sh` (idempotent).
- Restart the producer and confirm raw input resumes in the next window.
- If a consumer fell behind past retention, record the gap explicitly: the
  missing range cannot be recovered from Kafka.

## Escalation criteria

- Broker unavailable for more than 5 minutes.
- Raw input at zero for more than two windows with the producer reported running.
- Evidence of offset gaps (data deleted by retention before consumption).

## Limitations and safety

- SignalOps reads Kafka metadata and watermarks only; it never joins a consumer
  group or commits offsets, so it cannot cause or fix lag.
- Do not reset consumer-group offsets or Spark checkpoints during an
  investigation; doing so replays or skips evidence.
