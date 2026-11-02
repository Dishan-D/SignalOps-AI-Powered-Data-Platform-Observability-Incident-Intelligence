# SignalOps operational layer — reference

This document is the reference for what the operational layer measures, how it
decides, and what it guarantees. The README gives the overview and setup.

## Layering

```
src/signalops/
  sources/        read-only adapters: Postgres (read-only sessions), Kafka (metadata + assigned tail reads)
  services/       every operational query and derivation — the only place SQL lives
  retrieval/      BM25 runbook search over Markdown sections
  investigation/  agent loop, tool registry, providers, grounding, async jobs
  api/            FastAPI routes (thin adapters over services)
  slack/          /ops slash command (same services)
  dashboard/      Streamlit app over the API; pure display logic in data.py
```

The API, dashboard, agent tools and Slack all call `signalops.services`. None
of them issues queries of its own.

## What the pipeline had to change

Two signals existed only inside running processes, so they were persisted
(migration `0005_ops_telemetry.sql`, schema `ops`):

| Signal | Writer | Table |
|---|---|---|
| Spark Structured Streaming progress per micro-batch, query lifecycle | `forensics.streaming.progress` — a `StreamingQueryListener` registered by `job.py` when `SPARK_PROGRESS_DSN` is set | `ops.stream_progress`, `ops.stream_queries` |
| Ledger verification outcomes | `forensics.ledger.sealer.record_verification`, called after each periodic `verifier.verify` | `ops.ledger_verifications` |

The listener never raises into Spark and never blocks it: callbacks enqueue
into a bounded queue (oldest dropped when full) drained by a daemon thread.
If psycopg is missing or Postgres is down, the job runs exactly as before and
only telemetry is lost. Spark's UI REST API was not used because it does not
expose Structured Streaming progress.

## Measurement semantics

Every metric is a `Metric` with `state` ∈ `ok | unknown | unavailable | error`.
Only `ok` carries a value. `unknown` = source answered but has nothing to
compute from; `unavailable` = source not reachable / not configured; `error` =
reached, query failed. None of these is ever rendered as 0.

| Metric | Source | Semantics |
|---|---|---|
| `kafka.<topic>.records_in_window` | `offsets_for_times` + high watermark | Records appended in the window by record timestamp. No messages consumed. Lower bound if retention removed records inside the window. |
| `kafka.<topic>.retained_records` | watermarks | high − low per partition. Exact for this pipeline's idempotent, non-transactional producers; an upper bound under transactions. |
| `postgres.raw_events.landed_in_window` | `evidence.raw_events.landed_at` | Rows the Spark JDBC sink inserted in the window (Postgres clock). |
| `postgres.normalize_pending`, `…oldest_pending_age` | `normalized_at IS NULL` | Landing backlog waiting for the sealer's normalisation step. |
| `postgres.normalize_failures_in_window` | `normalize_error IS NOT NULL` | Rows that passed stream validation but failed the SQL transform. |
| `latency.landing.p50/p95` | `landed_at − ingested_at` | Kafka record CreateTime → Postgres insert. Includes Spark trigger wait, processing and JDBC write. Excludes normalisation and sealing. **Not** an end-to-end latency. |
| `latency.normalize.p50/p95` | `normalized_at − landed_at` | Landing → 3NF normalisation. |
| `spark.raw_rows_processed` | `numInputRows` of `normalized-events` | Every query reads `logs.raw` independently; this one's input is the raw consumption. |
| `spark.dlq_rows_written` / `spark.normalized_rows_written` | sink `numOutputRows` of `dead-letters` / `normalized-events` | `unknown` when the sink does not report (Spark sends −1). |
| `spark.max_offsets_behind_latest` | source metric `maxOffsetsBehindLatest`, latest batch | Spark's own lag measure at batch end. |
| `detections.scored_windows/flagged_windows` | `analytics.detections.scored_at` | Detector activity in the window. |
| `dlq.ratio` | DLQ / raw records in window (Kafka offsets) | Same window, same clock type (record timestamps). |

Stage counts share a window but not a clock, and in-flight records sit in one
stage and not yet the next, so the API reports stages side by side and never
subtracts them.

Counting series are zero-filled only when their query succeeded (an empty
bucket is then a real zero). Gauges (lag) are not zero-filled.

## Health policy

Components: `postgres`, `kafka`, `spark`, `detector`, `ledger`. Checks run in
parallel with per-source timeouts (Postgres connect 3 s / statement 5 s, Kafka
3 s) and are cached for 5 s. No LLM or Slack call is ever made.

| Status | Meaning |
|---|---|
| healthy | within policy |
| degraded | working, a signal is outside policy (stale query, missing topic, stalled sealing, stale verification) |
| unhealthy | reachable and failing (query terminated with an exception, ledger findings) |
| unavailable | cannot be reached |
| unknown | no signal to judge by (no stream telemetry, detector not deployed, never verified) |

Overall = worst *known* status; `unknown` alone never makes the pipeline
unhealthy, but all-unknown is `unknown`. Liveness (`/api/ops/livez`) is
process-only; readiness (`/api/ops/readyz`) requires Postgres.

## Incident candidates

The repository has no incident entity, so none was invented. Fixed rules run
over the signals above (`services/incidents.py`), each producing an
`IncidentCandidate` with id `<rule>:<scope>`, the facts that triggered it, a
severity from this policy, and suggested tools and runbook query. Candidates
are always labelled `status: candidate` — not confirmed incidents.

| Rule | Fires when | Severity |
|---|---|---|
| `stream_query_failed` | a query terminated with an exception | critical |
| `ledger_integrity` | latest verification has findings | critical |
| `stream_stalled` | no listener event > `SIGNALOPS_STREAM_STALE_SECONDS` (180) | high |
| `dlq_spike` | DLQ ≥ `SIGNALOPS_DLQ_MIN_RECORDS` (10) and ratio ≥ `SIGNALOPS_DLQ_RATIO_WARN` (5%) | high at ≥ `SIGNALOPS_DLQ_RATIO_HIGH` (25%), else medium |
| `normalize_failures` | any normalisation error in the window | medium |
| `ledger_seal_stalled` | unsealed events and no seal > 300 s | medium |
| `anomaly_cluster` | flagged detection windows for a host | high ≥ 5, medium ≥ 2, else low |
| `normalize_backlog` | pending > 50 000 rows or oldest > 600 s | low |

A rule whose inputs cannot be read is listed in `rules_skipped`, never treated
as "no incident".

## Investigation agent

* **Loop in code.** `investigation/agent.py` drives a manual tool-use loop
  (Claude via the Anthropic SDK; adaptive thinking; `output_config.effort`;
  strict tool schemas; server-side refusal fallbacks enabled by default and
  disable-able with `SIGNALOPS_LLM_SERVER_FALLBACKS=false`). Assistant content
  blocks are appended back verbatim each turn.
* **Closed, read-only tool set:** `get_pipeline_health`, `get_pipeline_metrics`,
  `get_recent_failures`, `get_dlq_summary`, `get_detection_details`,
  `get_host_timeline`, `get_ledger_status`, `search_runbooks`, plus
  `submit_report`. No SQL, shell, file or network tool. Inputs validated by
  Pydantic; outputs compacted to ≤ 9 000 chars.
* **Budgets:** ≤ 12 tool calls, ≤ 10 turns, 180 s wall clock, 60 s per model
  request (all configurable). Over-budget calls get an error result.
* **Untrusted data.** Each tool result is wrapped with an evidence id and an
  explicit "data, not instructions" notice; log messages and runbook text are
  never promoted to instructions. Unknown tool names (e.g. from an injected
  log line) are rejected with no side effect.
* **Grounding pass** (`ground_report`) before anything is returned:
  observations must cite evidence ids that were retrieved successfully;
  hypotheses must cite valid support; `high` confidence needs ≥ 2 independent
  tools or is downgraded; runbook citations must be sections actually returned
  by `search_runbooks`; root-cause assertions in the narrative are flagged;
  failed tools are added to `missing_information`. Every adjustment is listed
  in `validation_notes`, and any adjustment or failed tool makes the report
  `partial`.
* **Severity** comes from the incident rule, never from the model; free-form
  questions are `unknown`.
* **Failure:** provider errors (unconfigured, unavailable, timeout, refusal,
  no report) fail the job with the evidence gathered so far. No report is
  synthesised.

Providers: `anthropic` (Claude), `offline` (deterministic — calls the
incident's related tools, restates their summaries as observations, offers
rule-templated low-confidence hypotheses, and labels itself as using no
language model), `none` (investigations disabled; API returns 503).

Jobs run on a 2-worker pool, are kept in memory (≤ 200, lost on restart), and
are polled via `GET /api/ops/investigations/{job_id}`.

## Runbooks

Six Markdown runbooks in `runbooks/`, each with Purpose, Symptoms, Evidence to
collect, Diagnostic steps, Expected observations, Possible causes, Recommended
next steps, Escalation criteria, Limitations and safety. Retrieval is BM25
over `##`/`###` sections (headings weighted ×2; compound tokens such as
`unknown_category` and `logs.raw.dlq` indexed whole and split). Hits carry
source path, title, section, score, excerpt and matched terms. Embeddings were
not introduced: the corpus is small and its vocabulary is exact technical
terms, where lexical matching is the stronger signal.

## Slack

`POST /slack/commands` (mounted in the API) implements `/ops health`,
`/ops incidents`, `/ops investigate <id>`, `/ops runbook <query>`:

* signatures verified with `slack_sdk.signature.SignatureVerifier` (HMAC v0,
  5-minute replay window); bad or stale → 401;
* immediate ephemeral acknowledgement, work done in a background task and
  posted to `response_url`; investigations post start and result;
* `response_url` must be `https://hooks.slack.com/...` (no SSRF);
* duplicates (same `trigger_id`, or `X-Slack-Retry-Num`) are not reprocessed;
* `incidents` and `investigate` require `SLACK_ALLOWED_USER_IDS` (and
  `SLACK_ALLOWED_CHANNEL_IDS` if set); `health` and `runbook` are open to the
  workspace;
* without `SLACK_SIGNING_SECRET` the endpoint returns 404 and nothing else is affected.

Slack app setup: create an app, add a slash command `/ops` with request URL
`https://<public-host>/slack/commands`, copy the signing secret into
`SLACK_SIGNING_SECRET`. A bot token is not needed (responses use `response_url`).

## Security summary

* API binds to loopback in Compose; `SIGNALOPS_API_KEY` (X-API-Key, constant-time
  compare) is required whenever `APP_ENV != local`.
* Postgres sessions are `default_transaction_read_only=on` with a statement timeout.
* All SQL is module-level constants with bound parameters; identifiers from
  requests are validated (host names, incident ids, job ids) before use.
* Ground truth (`analytics.event_labels`, `analytics.detection_truth`,
  `eval_*` columns, `labels.ground_truth` inside DLQ payloads) is never read
  or is stripped before display; a test asserts no operational SQL references it.
* Payload previews are truncated to 240 characters.
