# SignalOps — Streaming Data Platform Observability & Incident Intelligence

SignalOps is a real-time security-telemetry pipeline (Kafka → Spark Structured
Streaming → PostgreSQL, with a transformer-based log-anomaly detector and a
tamper-evident evidence ledger) plus an **operational intelligence layer** that
makes the pipeline observable and easier to troubleshoot: a read-only
operational API, a Streamlit/Plotly dashboard, source-attributed runbook
retrieval, an evidence-grounded LLM investigation agent, and a Slack `/ops`
command.

The goal is to take an engineer from *"something is wrong with the data
pipeline"* to *"here is the observed evidence, here are possible explanations,
here is the relevant runbook section, and here are the next steps"* — without
the system inventing metrics, evidence or root causes.

> **Status at a glance** — see [Implementation status](#implementation-status)
> for exactly what has been verified and how.

## Contents

- [Architecture](#architecture)
- [The streaming pipeline](#the-streaming-pipeline)
- [The operational layer](#the-operational-layer)
- [API](#api)
- [Investigation agent](#investigation-agent)
- [Slack](#slack)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [Testing](#testing)
- [Controlled incident demonstration](#controlled-incident-demonstration)
- [Implementation status](#implementation-status)
- [Limitations and future work](#limitations-and-future-work)

Detailed reference (metric semantics, health and incident policies, agent
guarantees): [docs/signalops.md](docs/signalops.md). Pipeline design decisions:
[docs/architecture.md](docs/architecture.md).

## Architecture

```
  synthetic telemetry (producer)
            │
            ▼
   Kafka 3.9 (KRaft) ── logs.raw ──────────────┐
            │                                  │
            ▼                                  │
   Spark 4.0 Structured Streaming              │  offsets / watermarks
   parse → validate → normalise ──► logs.raw.dlq (rejected, with reason)
            │        │                         │
            │        ├─► logs.normalized ─► LogBERT scorer ─► alerts.anomalies
            │        ├─► features.host_activity / features.peer_connections
            │        └─► PostgreSQL evidence.raw_events ─► sealer: normalise → 3NF
            │                                   │               seal → ledger blocks
            │  StreamingQueryListener           │               verify → ops.ledger_verifications
            └──────────► ops.stream_progress ◄──┘
                                    │
                     ┌──────────────┴──────────────┐
                     │  signalops.services          │  (single implementation of
                     │  read-only Postgres + Kafka  │   every operational query)
                     └──────────────┬──────────────┘
                                    │
                         FastAPI  /api/ops/*
                ┌───────────────────┼────────────────────┐
                ▼                   ▼                    ▼
         Streamlit dashboard   Investigation agent    Slack /ops
         (Plotly)              (Claude tool use,      (signed, async)
                               fixed read-only tools,
                               runbook search)
```

Nothing in the operational layer is on the ingestion path. Kafka, Spark, the
detector, the sealer and ledger verification run identically whether the API,
the LLM provider or Slack are up or not.

## The streaming pipeline

| Stage | Implementation |
|---|---|
| Telemetry | `forensics.ingestion` — synthetic ECS-style events: benign activity plus SSH brute force, reverse shell, C2 beaconing, privilege escalation, exfiltration. Ground-truth labels ride in `labels.ground_truth` for evaluation only. |
| Kafka | `apache/kafka:3.9.0`, KRaft, six topics created by `scripts/create-topics.sh`: `logs.raw`, `logs.normalized`, `logs.raw.dlq`, `features.host_activity`, `features.peer_connections`, `alerts.anomalies`. |
| Spark | `forensics.streaming.job` — five independent queries over `logs.raw`. Validation (`normalize._validation_error`) routes failures to `logs.raw.dlq` with the first failing rule (`malformed_json`, `unknown_category`, `severity_out_of_range`, …) and the original payload. |
| PostgreSQL | `postgres:16-alpine`. Flat landing table `evidence.raw_events` (Spark JDBC sink) drained by `evidence.normalize_raw_events()` into a 3NF, monthly-partitioned `evidence.events`. Labels live separately in `analytics.event_labels`. |
| Detector | Drain-style template mining + compact LogBERT-style transformer trained on benign data (`forensics.inference`); the scorer writes per-host windows to `analytics.detections`. |
| Ledger | Per-event SHA-256 digests by trigger; Merkle-rooted, hash-chained blocks sealed by `forensics.ledger.sealer`; out-of-database verifier with inclusion proofs. |

Previously reported synthetic evaluation of the detector (precision 0.853,
recall 0.794, F1 0.833, PR-AUC 0.837) comes from `forensics.inference.evaluate`
on synthetic data; it was **not re-run** as part of the SignalOps work and says
nothing about real-world performance.

## The operational layer

Code lives in `src/signalops/` (see [docs/signalops.md](docs/signalops.md#layering)).

**Two small pipeline additions** were needed because the signals existed only
inside running processes (migration `0005_ops_telemetry.sql`, schema `ops`):

1. `forensics.streaming.progress` — a Spark `StreamingQueryListener` that
   persists per-batch progress (input rows, sink output rows, rates,
   `maxOffsetsBehindLatest`, watermark) and query lifecycle (including
   termination exceptions). Enabled by `SPARK_PROGRESS_DSN`; never raises into
   or blocks Spark.
2. The sealer now records each periodic ledger verification result.

**Metrics** (all with source, window and explicit state — `ok`, `unknown`,
`unavailable`, `error`; a missing value is never shown as 0):

| Area | Metrics |
|---|---|
| Ingestion | raw and DLQ records in window (Kafka `offsets_for_times`; nothing consumed), retained records |
| Processing | Spark raw rows processed, DLQ / normalised rows written, processing rate, offsets behind latest, per-query liveness |
| Data quality | DLQ ratio, sampled rejection reasons, normalisation failures and backlog |
| Latency | landing (Kafka record time → Postgres insert) and normalisation p50/p95 — explicitly *not* end-to-end |
| Detection | windows scored / flagged, time since last score |
| Integrity | blocks, unsealed backlog, time since seal, latest verification and findings |

**Health** for `postgres`, `kafka`, `spark`, `detector`, `ledger` as
`healthy | degraded | unhealthy | unavailable | unknown`, checked in parallel
with per-source timeouts and no LLM involvement.

**Incident candidates** are derived by documented, deterministic rules
(`dlq_spike`, `stream_query_failed`, `stream_stalled`, `normalize_failures`,
`normalize_backlog`, `ledger_integrity`, `ledger_seal_stalled`,
`anomaly_cluster`), each with a policy-defined severity. They are labelled
candidates — the repository has no incident entity and none was invented.

**Dashboard** (`src/signalops/dashboard/app.py`): health and candidates,
ingestion/processing charts, data quality (DLQ reasons, samples with labels
stripped), anomalies with per-detection evidence and host timelines, evidence
integrity, and an investigation panel that polls jobs without blocking the UI.
It reads only the API.

**Runbooks** (`runbooks/`): Kafka ingestion failures, Spark processing delays,
schema validation errors, DLQ investigation, anomaly investigation, evidence
ledger verification — each with symptoms, evidence to collect, diagnostic
steps, expected observations, causes, next steps, escalation criteria and
safety notes. Retrieval is BM25 over sections, with source and section
attribution.

## API

`uvicorn signalops.api.app:app` — OpenAPI docs at `/docs`. Every route is
read-only and calls the shared services.

| Method & path | Purpose |
|---|---|
| `GET /api/ops/livez`, `/api/ops/readyz` | liveness (process) / readiness (Postgres reachable) |
| `GET /api/ops/health` | component health, LLM-independent |
| `GET /api/ops/metrics?window_minutes=` | metrics + time series + stream query state |
| `GET /api/ops/incidents`, `/api/ops/incidents/{id}` | rule-derived candidates |
| `GET /api/ops/dlq/summary` | DLQ volume, ratio, reasons, sanitised samples, normalisation failures |
| `GET /api/ops/detections`, `/api/ops/detections/{id}` | paginated detections; one detection with signals, thresholds, events |
| `GET /api/ops/hosts/{host}/timeline` | bounded event + detection timeline |
| `GET /api/ops/ledger/status` | sealing state and latest verification |
| `GET /api/ops/runbooks/search?q=` | runbook sections with attribution |
| `POST /api/ops/investigate` | start an investigation → `202` + job (`503` if no provider, `404` unknown candidate, `429` queue full) |
| `GET /api/ops/investigations`, `/api/ops/investigations/{job_id}` | provider status; job status and report |
| `POST /slack/commands` | Slack slash command (404 unless configured) |

Errors use one envelope: `{"error": {"code", "message", "source"?}}`. Data
source failures return `503` naming the source. Inputs are bounded (windows
5–10080 min, limits ≤ 500, validated host names and ids). `X-API-Key` is
enforced when `SIGNALOPS_API_KEY` is set and mandatory outside `APP_ENV=local`;
Compose binds the API to loopback.

## Investigation agent

A manual tool-use loop over Claude (`claude-opus-5-5` by default, via the
Anthropic SDK) with a closed, read-only tool set: `get_pipeline_health`,
`get_pipeline_metrics`, `get_recent_failures`, `get_dlq_summary`,
`get_detection_details`, `get_host_timeline`, `get_ledger_status`,
`search_runbooks`, and `submit_report`. The model picks tools; code enforces
budgets (12 tool calls, 10 turns, 180 s), validates every argument, wraps every
result as untrusted data with an evidence id, and then **grounds** the
submitted report: observations and hypotheses citing evidence that was never
retrieved are removed, high confidence on a single source is downgraded,
runbook citations must be sections actually retrieved, and root-cause
assertions are flagged. Severity comes from the incident rule, never the
model. Provider failures fail the job with the evidence gathered so far — no
report is fabricated.

The report separates `observations` (claim + evidence ids + sources) from
`potential_causes` (hypothesis + supporting evidence + qualitative,
uncalibrated confidence), and lists runbook sections, recommended steps,
missing information, limitations, the full evidence trail and validation notes.

`SIGNALOPS_LLM_PROVIDER=offline` runs the same loop and tools with a
deterministic investigator that restates tool results and labels itself as
using no language model — for demos and environments without an API key.

## Slack

`/ops health`, `/ops incidents`, `/ops investigate <incident_id>`,
`/ops runbook <query>`. Requests are verified with the signing secret
(`slack_sdk` `SignatureVerifier`, 5-minute replay window), acknowledged
immediately, processed in the background and answered via `response_url`
(restricted to `hooks.slack.com`). Duplicates and retries are not reprocessed.
`incidents` and `investigate` require allow-listed user ids. Without
`SLACK_SIGNING_SECRET` the endpoint is disabled and nothing else changes.
Setup steps: [docs/signalops.md](docs/signalops.md#slack).

## Getting started

Prerequisites: Docker with Compose, Python 3.12 for local development.

```bash
cp .env.example .env          # set POSTGRES_PASSWORD; optionally SIGNALOPS_LLM_PROVIDER / ANTHROPIC_API_KEY
docker compose up -d --build  # Kafka, Postgres, migrate, Spark, producer, sealer, ops-api, dashboard
docker compose ps
```

- API: <http://127.0.0.1:8000/docs> (`SIGNALOPS_API_PORT`)
- Dashboard: <http://127.0.0.1:8501> (`SIGNALOPS_DASHBOARD_PORT`)
- Detector (optional): `make train` then `docker compose --profile detect up -d scorer`

Local development without containers for the operational layer:

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt -r requirements-ops.txt
make ops-api         # uvicorn on :8000 against POSTGRES_* / KAFKA_BOOTSTRAP_SERVERS
make ops-dashboard   # streamlit on :8501 against SIGNALOPS_API_URL
```

## Configuration

All configuration is environment-based; `.env.example` documents every
variable with placeholders only. SignalOps-specific settings:

| Variable | Purpose |
|---|---|
| `SIGNALOPS_API_KEY` | API key (X-API-Key); required when `APP_ENV` ≠ `local` |
| `SIGNALOPS_LLM_PROVIDER` | `anthropic`, `offline` or `none` (default: `anthropic` if `ANTHROPIC_API_KEY` is set, else `none`) |
| `ANTHROPIC_API_KEY`, `SIGNALOPS_LLM_MODEL`, `SIGNALOPS_LLM_EFFORT` | Claude credentials, model (`claude-opus-5-5`), effort (`medium`) |
| `SIGNALOPS_LLM_REQUEST_TIMEOUT_SECONDS`, `SIGNALOPS_INVESTIGATION_TIMEOUT_SECONDS`, `SIGNALOPS_MAX_TOOL_CALLS` | agent bounds |
| `SLACK_SIGNING_SECRET`, `SLACK_ALLOWED_USER_IDS`, `SLACK_ALLOWED_CHANNEL_IDS` | Slack integration |
| `SPARK_PROGRESS_DSN` | enables the Spark progress listener (set in Compose) |
| `SIGNALOPS_*_THRESHOLD…` (`SIGNALOPS_STREAM_STALE_SECONDS`, `SIGNALOPS_DLQ_RATIO_WARN`, …) | health / incident policy |

The core pipeline needs none of these. Never commit a populated `.env`.

## Testing

```bash
make test        # core suite incl. SignalOps (no infrastructure; DB/Spark suites skip)
make test-ops    # SignalOps suite only
make test-db     # database suite incl. SignalOps SQL against a real Postgres (destructive: use a throwaway DB)
make lint typecheck
```

Results on this branch (Windows, Python 3.12.6):

| Suite | Result |
|---|---|
| Core + SignalOps (`pytest`, no infrastructure) | **357 passed**, 47 skipped (DB suite without Postgres; Spark suite without pyspark) |
| Database suite against PostgreSQL 16 (throwaway container) | **47 passed** — existing evidence/ledger tests plus 5 SignalOps query tests |
| Spark suite | not run here: needs `pyspark==4.0.0` and JDK 17/21 (`make test-spark`) |
| Ruff | clean |
| mypy | 5 errors, all pre-existing (`common/kafka.py`, `inference/model.py`, `inference/scorer.py`); none in new code |

The SignalOps tests use deterministic fakes for Postgres, Kafka and the LLM
(a scripted provider) and cover: metric aggregation; missing, stale, zero vs
unknown vs unavailable; Kafka and DB outages; terminated Spark queries; ledger
failures; DLQ sanitisation of ground-truth labels; incident rules and bounds;
API status codes, validation, auth and dependency failures; runbook relevance,
attribution and malformed documents; agent tool selection, argument
validation, tool failures, partial results, timeouts, refusals, malformed
reports, unsupported claims, bounded loops and prompt injection through log
messages and runbooks; Anthropic request shape; Slack signatures, staleness,
duplicates, authorisation, SSRF guard and async investigations; dashboard
transforms; Spark progress parsing and sealer recording.

## Controlled incident demonstration

`make demo-incident` (or `python scripts/demo_incident.py --api http://127.0.0.1:8000`)
runs against the live stack and asserts each step:

1. reads baseline health and DLQ counts from the API;
2. publishes a burst of real generator events, each with one deliberate
   validation defect (`scripts/inject_bad_events.py`: unknown category,
   out-of-range severity, unparseable timestamp, truncated JSON) to `logs.raw`;
3. waits until the API's DLQ count — derived from Kafka offsets — reflects the
   rejected records Spark routed to `logs.raw.dlq`;
4. confirms the `dlq_spike:logs.raw.dlq` candidate and its sampled reasons;
5. starts an investigation and prints observations, hypotheses, runbook
   sections and the evidence trail;
6. confirms Spark is still processing.

LLM-outage variant: start `ops-api` with an unusable provider (e.g.
`SIGNALOPS_LLM_PROVIDER=anthropic ANTHROPIC_API_KEY=invalid` or a tiny
`SIGNALOPS_LLM_REQUEST_TIMEOUT_SECONDS`) and run
`scripts/demo_incident.py --expect-llm-failure`: the investigation fails
explicitly with its partial evidence while health, metrics and Spark carry on.

**Verified run** (live Compose stack, offline provider, 15-minute window):

```
[2] Injecting 400 invalid events onto logs.raw
    {"published": 400, "defects": {"unknown_category": 100, "severity_out_of_range": 100,
                                   "unparseable_timestamp": 100, "malformed_json": 100}}
[3] DLQ records: 400 (+400), ratio 24.3%
    sampled reasons: severity_out_of_range=34, unparseable_timestamp=33, unknown_category=32, malformed_json=31
[4] dlq_spike:logs.raw.dlq [medium] 400 records dead-lettered (24.0% of raw input)
[6] OBSERVED   get_dlq_summary: dlq.records_in_window=400; dlq.ratio=0.24; sampled reasons ...   (E1)
    OBSERVED   get_pipeline_metrics: kafka logs.raw in window=1707; spark.dlq_rows_written=400   (E2)
    HYPOTHESIS [low] upstream producer/schema change emitting records failing 'severity_out_of_range'  (E0, E1)
    RUNBOOK    runbooks/schema-validation-errors.md § Error code reference
[7] health healthy; spark healthy: 5 streaming queries reporting
```

LLM-outage run (`ops-api` restarted with an invalid Anthropic key): the
investigation failed with `LLM provider failed (unconfigured): Claude API
rejected the credentials`, returned only the evidence gathered (`incident_rules`)
and no report, while health stayed `healthy` and Spark's processed rows in the
window rose from 2,586 to 3,436. The dashboard was rendered headlessly against
the same stack (Streamlit `AppTest`): no exceptions, 19 metric tiles and 5
charts populated from the API; the detector tiles showed "—" because the scorer
was not deployed.

## Implementation status

| Area | Status |
|---|---|
| Streaming pipeline, detector, ledger | existing; preserved (one additive listener, one additive sealer call) |
| Operational services, metrics, health, incident rules | implemented, unit-tested, SQL verified against Postgres 16 |
| FastAPI operational API | implemented and tested (TestClient + live stack) |
| Runbooks + retrieval | implemented and tested |
| Investigation agent — orchestration, grounding, offline provider | implemented and tested with a scripted provider |
| Investigation agent — live Claude calls | implemented; request shape tested with a fake client; **not verified against the live API** (no API key used in development) |
| Slack `/ops` | implemented; signature verification and flows tested against Slack's documented scheme; **not verified against a real Slack workspace** |
| Dashboard | implemented; display logic unit-tested; served against the live stack |
| Spark progress listener | implemented; parsing/writer unit-tested; exercised on the live stack |

## Limitations and future work

- Synthetic telemetry only; detector metrics are from synthetic evaluation.
- Records are unsealed until the next seal; integrity status is the latest
  sealer verification, not a live check (`make ledger-verify` for on-demand).
- Investigation jobs are in memory (lost on API restart); no persistence or
  multi-instance coordination.
- DLQ reason counts come from a bounded tail sample; the response says when the
  sample does not cover the window.
- Landing latency covers Kafka → Postgres landing only; there is no
  instrumented end-to-end (producer → sealed) latency.
- Automated DLQ replay is not implemented (runbooks describe the manual path).
- Future: persisted investigations, live verification of Claude and Slack
  paths in CI with real credentials, consumer-group lag for the scorer, DLQ
  replay tooling, alert routing from incident candidates.
