# Schema Validation Errors

## Purpose

Diagnose records that the Spark normaliser rejects at validation time. Every
rejected record is routed to `logs.raw.dlq` with the *first* failing rule in its
`error` field (see `forensics/streaming/normalize.py::_validation_error`). This
runbook maps each error code to its likely cause and the evidence that confirms
it.

## Symptoms

- `dlq_spike:logs.raw.dlq` incident candidate in SignalOps.
- `dlq.ratio` above the warning threshold (default 5%) on `/api/ops/dlq/summary`.
- `spark.dlq_rows_written` rising while `spark.normalized_rows_written` falls
  for the same window.
- Fewer rows landing in `evidence.raw_events` than records arriving on `logs.raw`.

## Evidence to collect

1. `get_dlq_summary` for the affected window: DLQ count, raw count, ratio, and the
   sampled `error` reason counts.
2. Whether the sample covers the window (`sample_covers_window`). If it does not,
   the reason counts are a sample of the newest records, not a census.
3. Two or three sanitised `payload_preview` values for the dominant reason.
4. `get_pipeline_metrics` to see when the rejection rate changed.
5. Producer deploy or configuration changes around the onset time (outside SignalOps).

## Diagnostic steps

1. Identify the dominant `error` code in the sample and look it up below.
2. Compare the onset time of the DLQ increase with producer restarts
   (`make producer-logs`) and schema-version changes (`schema_version` in the payload).
3. Check whether the rejected payloads share a `schema_version`, a host, or a
   dataset. A single host suggests a misbehaving agent; all hosts suggests a
   producer-side or schema change.
4. Confirm the healthy path is still flowing: `spark.normalized_rows_written` should
   be non-zero unless every record is being rejected.

### Error code reference

| error | Rule that failed | Typical cause |
|---|---|---|
| `empty_payload` | Kafka value is null | Producer sent a tombstone or an empty message |
| `malformed_json` | Payload is not valid JSON | Truncated writes, wrong serialiser, binary payload on the topic |
| `missing_event_id` | `event_id` null or blank | Producer bug; event built without an id |
| `missing_timestamp` | `timestamp` absent | Field renamed or dropped upstream |
| `unparseable_timestamp` | `timestamp` not in the expected ISO-8601 format | Format change (e.g. epoch millis, missing timezone) |
| `missing_host_name` | `host.name` absent | Agent misconfiguration on one or more hosts |
| `missing_category` | `category` absent | Schema change upstream |
| `unknown_category` | `category` not in authentication/process/network/file | New event type not yet supported by the pipeline |
| `unknown_outcome` | `outcome` not success/failure/unknown | New outcome value upstream |
| `severity_out_of_range` | `severity` outside 0..7 | Different severity scale (e.g. 0..10) adopted upstream |

## Expected observations

- A genuine upstream schema change produces **one dominant error code**, a sharp
  onset, and payloads that are otherwise well-formed.
- Random corruption (network, serialiser) produces mostly `malformed_json` spread
  across hosts with no clean onset.
- A controlled injection (e.g. `scripts/inject_bad_events.py`) produces a burst
  whose reasons match the injected mix exactly and stops when the injection stops.

## Possible causes

- Producer released with a changed event shape or field name.
- A new event category or outcome introduced upstream before the pipeline supports it.
- A different severity scale adopted by a log source.
- A serialiser or encoding change producing invalid JSON.
- Deliberate test traffic.

## Recommended next steps

- If the change is intentional upstream, extend `VALID_CATEGORIES` /
  `VALID_OUTCOMES` / the severity range in `forensics/streaming/schema.py`, add a
  Spark test, and redeploy; then replay the DLQ records (the original payload is
  preserved byte-for-byte for exactly this purpose).
- If unintentional, roll back the producer change and confirm the DLQ ratio
  returns to baseline in the next window.
- Record the onset time, dominant error and affected hosts in the incident notes.

## Escalation criteria

- DLQ ratio above 25% for more than one window: evidence is being lost to the
  healthy path; escalate to the pipeline owner.
- `spark.normalized_rows_written` at zero while raw input continues: total
  ingestion outage for evidence; escalate immediately.
- Rejections concentrated on hosts that are also under an anomaly investigation:
  involve the security on-call — tampered telemetry is a possibility.

## Limitations and safety

- Only the first failing rule is recorded; a record may fail several.
- Payload previews are truncated and have ground-truth labels removed; do not
  reconstruct full payloads into tickets or chat.
- Do not delete or compact `logs.raw.dlq` while an investigation is open: it is
  the only copy of the rejected input.
