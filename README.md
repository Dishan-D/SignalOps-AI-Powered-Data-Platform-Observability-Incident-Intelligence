# Enterprise Cyber-Forensics & Log Anomaly Pipeline

A real-time, fault-tolerant log ingestion and anomaly-detection pipeline for
security telemetry. Kafka streams the events, Spark normalises and windows them,
a transformer-based log model scores them for attacks, and PostgreSQL stores the
results in a tamper-evident Merkle-chained evidence ledger.

**Stack:** Python 3.12 · Apache Kafka 3.9 (KRaft) · Apache Spark 4.0 Structured
Streaming · PyTorch · PostgreSQL 17 · Docker Compose · pytest / ruff / mypy

Two things distinguish this from a typical streaming demo:

1. **It detects attacks, not just throughput.** A LogBERT-style masked-language
   model trained on benign log-key sequences reaches **precision 0.85 / recall
   0.79 (PR-AUC 0.84)** at a 1% attack base rate — against **F1 0.39** for a
   trivial "unseen log template" rule.
2. **It can prove the evidence was not altered.** A two-layer ledger (per-event
   SHA-256 digests sealed into Merkle-rooted chained blocks) detects a
   single-byte edit across 50,000 events in about a second — including the case
   where an attacker rewrites an event *and* its digest together.

> **Status: complete and verified end-to-end.** All four tiers run together in
> Docker Compose; **270 tests** pass across four infrastructure suites, with
> `ruff` and `mypy` clean.

---

## Architecture

```
   ┌──────────────────┐
   │  log_producer ✅ │  synthetic ECS telemetry, seedable, 25 ev/s default
   └────────┬─────────┘
            │ keyed by host.name
            ▼
   ┌──────────────────────────────┐
   │  Kafka  (KRaft, no ZooKeeper)│
   │        logs.raw              │
   └────────┬─────────────────────┘
            ▼
   ┌────────────────────────────────────────┐
   │  Spark Structured Streaming ✅          │
   │  parse → validate → flatten → window   │
   └───┬────────┬───────────┬───────────┬───┘
       │        │           │           │
  invalid    normalised  features   JDBC append
       │        │           │           │
       ▼        ▼           ▼           ▼
 logs.raw.dlq  logs.    features.*   evidence.raw_events
               normalized             (landing table)
                                           │
                                  evidence.normalize_raw_events()
                                           │  set-based ELT, 9.6k rows/s
                                           ▼
                          ┌────────────────────────────────┐
                          │  PostgreSQL ✅                  │
                          │  evidence.*   3NF, partitioned │
                          │  analytics.*  labels, scores   │
                          │  ledger.*     hash chain (P4)  │
                          └────────────────────────────────┘
                                           │
                     ┌─────────────────────▼──────────────────┐
                     │  Detection tier ✅                      │
                     │  Drain templates → log keys → LogBERT  │
                     │  → calibrated thresholds               │
                     └──────┬──────────────────────┬──────────┘
                            ▼                      ▼
                    alerts.anomalies      analytics.detections
```

### Layout

```
.
├── docker-compose.yml         # Kafka (KRaft) + Postgres + producer
├── docker/Dockerfile          # multi-stage, non-root Python base image
├── docker/Dockerfile.spark    # Spark image, connector JARs baked in
├── db/
│   ├── init/                  # runs once on an empty volume
│   └── migrations/            # versioned DDL, applied by scripts/migrate.py
├── scripts/
│   ├── create-topics.sh       # idempotent topic provisioning
│   ├── migrate.py             # forward-only migration runner
│   └── find-java.sh           # picks a Spark-compatible JDK
├── src/forensics/
│   ├── common/                # config, JSON logging, Kafka sink  ← shared
│   ├── ingestion/             # schemas, generators, log_producer  ✅
│   ├── streaming/             # schema, normalize, features, job   ✅
│   ├── inference/             # templates, vocabulary, sequences,   ✅
│   │                          #   model, train, evaluate, scorer
│   └── ledger/                # chain, verifier, sealer            ✅
└── tests/                     # 269 tests
    ├── (core)                 # 135 — no infrastructure needed
    ├── model/                 #  49 — needs PyTorch
    ├── spark/                 #  43 — needs a JVM
    └── db/                    #  42 — needs PostgreSQL
```

Each tier depends only on `common` and on the wire contract in
`ingestion/schemas.py` — never on another tier's internals.

---

## Quick start

### Without Docker (30 seconds, no broker)

The producer has a dry-run mode that prints events to stdout, so the whole
ingestion path is runnable and testable with zero infrastructure:

```bash
make venv
make demo          # 20 sample events
make check         # lint + typecheck + 135 core tests
```

```bash
# pipe it anywhere — stdout is pure NDJSON, logs go to stderr
PYTHONPATH=src PRODUCER_DRY_RUN=true PRODUCER_MAX_EVENTS=200 \
  .venv/bin/python -m forensics.ingestion.log_producer \
  | jq -c 'select(.value.labels.ground_truth) | .value.message'
```

### Database, ledger and detector without Docker

`make seed` loads generated evidence straight into PostgreSQL, bypassing Kafka
and Spark — enough to exercise the 3NF transform, the ledger and tamper
detection on a machine with nothing but Python and Postgres:

```bash
# one-time: create the database and apply the schema
createdb forensics
psql -d forensics -f db/init/00_bootstrap.sql
export POSTGRES_DB=forensics POSTGRES_USER="$(whoami)" POSTGRES_PASSWORD=
.venv/bin/python scripts/migrate.py

make seed                                     # 20k events -> normalised -> sealed
.venv/bin/python scripts/verify_ledger.py     # INTACT
```

Then prove the tamper detection actually works:

```bash
psql -d forensics -c "UPDATE evidence.events SET message='scrubbed'
  WHERE event_id=(SELECT event_id FROM evidence.events LIMIT 1);"
.venv/bin/python scripts/verify_ledger.py     # COMPROMISED, exit 1
```

### Full stack

```bash
cp .env.example .env      # then set POSTGRES_PASSWORD
make up                   # Kafka, Postgres, migrations, producer, Spark
make producer-logs        # structured JSON logs from the producer
make spark-logs           # streaming job progress
make consume              # tail 20 live events off logs.raw
make evidence             # row counts across the evidence model
make normalize            # drain the landing table into the 3NF model manually
make ledger-status        # chain head, block count, unsealed backlog
make ledger-verify        # verify integrity from OUTSIDE the database
make train                # train the detector (explicit, not part of `up`)
make detect               # start the streaming scorer
make alerts               # most recent flagged detections
make detection-quality    # precision/recall of stored verdicts
make tools                # optional Kafka UI on http://localhost:8080
make clean                # tear down and delete volumes
```

Startup is ordered by health, not by `sleep`: `kafka-init` waits for a broker
that answers API requests, `spark` waits for `kafka-init` **and** `migrate` to
exit successfully, so no service starts against a half-built dependency.

Kafka is reachable at `localhost:29092` from the host and `kafka:9092` from
inside the network. Postgres is on `localhost:5432`.

---

## Verified end-to-end

Not "should work" — this is a running stack, observed after ~13 minutes of
continuous operation with every service healthy:

```
$ docker compose ps
forensics-kafka      Up 13 minutes (healthy)
forensics-postgres   Up 13 minutes (healthy)
forensics-producer   Up 13 minutes
forensics-scorer     Up  5 minutes
forensics-sealer     Up 13 minutes
forensics-spark      Up 13 minutes

Kafka topics                        PostgreSQL
  logs.raw                  14751     raw_events   14762
  logs.normalized           14762     events       14012
  logs.raw.dlq                  0     hosts           12
  features.host_activity      231     addresses     1850
  features.peer_connections  1032     labels         429
  alerts.anomalies             60

$ make ledger-verify
INTACT — 14762 events, 20 blocks, 0 unsealed
```

Tamper detection in that same live stack — altering one log message 5,000
events deep:

```
$ make ledger-verify
COMPROMISED (1 findings) — 19262 events, 26 blocks, 0 unsealed
  event_modified event e828d6e8-...: recomputed af364795947aa14a... but ledger holds a483e07b28d3f361...
```

Zero dead letters across ~15k events, and the ledger seals continuously with no
unsealed backlog.

---

## The event contract

Events follow the **Elastic Common Schema**, so a real Filebeat/Auditbeat feed
can replace the producer without touching anything downstream.

```json
{
  "event_id": "65d78cbd-03f2-41a5-a03e-f1cb103776c6",
  "timestamp": "2026-09-09T06:53:44.532+00:00",
  "category": "network",
  "action": "network_flow",
  "outcome": "success",
  "severity": 3,
  "message": "netflow: 10.20.0.11:37103 -> 192.0.2.61:443 proto=https sent=1242 recv=414",
  "host":    { "name": "api-01.corp.local", "ip": "10.20.0.11", "os_family": "linux" },
  "dataset": "network.flow",
  "network": { "source_ip": "10.20.0.11", "destination_port": 443, "bytes_sent": 1258, "...": "..." },
  "labels":  { "ground_truth": { "is_anomaly": true, "scenario": "c2_beaconing", "campaign_id": "7b24...", "step": 0 } },
  "schema_version": "1.0.0"
}
```

`message` keeps the raw unstructured log line — that is what the Phase 3 log
parser consumes; the structured fields exist for correlation and evidence
presentation.

**Records are keyed by `host.name`.** All events for a machine therefore land on
one partition and arrive in order, which turns Phase 2's per-host stateful
windows (failed-login bursts, beacon intervals) into partition-local operations
instead of a shuffle.

### Attack scenarios

The generator does not emit random noise — it emits correlated campaigns that
share a `campaign_id` and carry ordered `step` numbers:

| Scenario | Shape | Detection signal |
|---|---|---|
| `ssh_brute_force` | 12–40 failures, one source IP, one host; 25% end in success | failure burst + rare source |
| `reverse_shell` | suspicious `execve` then an outbound socket | command-line tradecraft |
| `c2_beaconing` | 6–14 callbacks at a fixed interval, ±5% jitter | periodicity + uniform payload size |
| `privilege_escalation` | sudo failures → success → `usermod -aG sudo` | sequence, not any single event |
| `data_exfiltration` | staging `tar` then an 80–900 MB upload | volume anomaly + off-baseline peer |

> ⚠️ **`labels.ground_truth` is the evaluation label set and must be stripped
> before feature extraction** (`GROUND_TRUTH_LABEL` in `generators.py`).
> Leaving it in lets the model read the answer off its own input.

`PRODUCER_ANOMALY_RATE` is the target fraction of *events* that are malicious,
held on target by a closed loop in the generator. Real base rates are far below
1%; the 0.03 default keeps class imbalance realistic without making Phase 3
untrainable. All synthetic external addresses come from RFC 5737 documentation
ranges, so nothing routable ever appears in the data — enforced by a test.

---

## Stream processing (Phase 2)

`logs.raw` → parse → validate → flatten → four sinks.

**Explicit schema, never inferred.** Inference needs a scan a stream cannot do,
and it silently changes shape when the data does. The declared StructType lives
in `streaming/schema.py`, and a test fails the build if it drifts from the
producer's dataclasses.

**Validation routes, it does not discard.** Each record gets a specific failure
reason (`malformed_json`, `unparseable_timestamp`, `unknown_category`,
`severity_out_of_range`, …) and lands on `logs.raw.dlq` with its payload
preserved byte-for-byte for replay. Parsing runs in PERMISSIVE mode with a
corrupt-record column: FAILFAST would abort the whole micro-batch on one bad
record, which is precisely the outage a DLQ exists to prevent.

**Two feature grains**, because the detections need different ones:

| Stream | Grain | Window | Catches |
|---|---|---|---|
| `features.host_activity` | (window, host) | 1 min / 30 s slide | brute force, escalation, exfiltration volume |
| `features.peer_connections` | (window, host, dest IP) | 10 min / 5 min slide | C2 beaconing |

The peer window is deliberately ten times longer: a beacon on a 300-second
interval produces *no* samples in a one-minute window, so short windows cannot
see periodicity by construction. Beacon regularity is computed as a coefficient
of variation over inter-arrival gaps using higher-order SQL (`array_sort` /
`zip_with` / `aggregate`) rather than a Python UDF, so it stays on the JVM
codegen path. Fewer than two gaps yields `NULL`, not `0.0` — reporting zero
would fabricate a perfect beacon out of two events.

Windows slide rather than tumble: a burst straddling a tumbling boundary is
split in half and can fall under threshold on both sides.

## Evidence store (Phase 2)

Spark appends flat rows to `evidence.raw_events`; a set-based SQL transform
resolves dimensions in bulk and populates the 3NF model. Doing dimension lookups
*in Spark* would mean a round trip per row, or broadcasting every dimension into
executor memory — both fight the database for something it is already good at.
Landing first also decouples availability: if normalisation is mid-deploy,
ingestion keeps landing evidence rather than dropping it.

**Where normalisation stops.** Repeating *entities* (hosts, users, process
images, IP addresses, datasets) become relations. Fixed closed domains
(`category`, `outcome`, `direction`) become ENUM types — a lookup table for a
three-value domain buys a join and no integrity the type system wasn't already
giving. `message` stays on the fact: it is the raw log line the Phase 3 model
consumes, and it is not a transitive dependency on a non-key attribute.

The address dimension is keyed on **IP alone, not (IP, port)**. That was
measured, not assumed: with random ephemeral source ports, `(ip, port)` produced
4,039 dimension rows for 4,000 facts — one row per fact, two extra joins, zero
compression. The same data holds 1,361 distinct addresses. An address is an
entity that recurs and that threat intelligence attaches to; a port is an
attribute of a single flow, so ports live on the fact table.

**Indexing**, verified with `EXPLAIN ANALYZE` rather than asserted:

| Index | Serves |
|---|---|
| `(host_id, occurred_at DESC)` | "show me this host's timeline" — the most common investigation query |
| partial on `occurred_at` `WHERE outcome='failure'` | authentication investigations; small and hot (Heap Fetches: 0) |
| GIN `gin_trgm_ops` on `message` | leading-wildcard `LIKE '%/dev/tcp/%'` — a B-tree cannot serve this at any size |
| `(destination_address_id, occurred_at DESC)` | the pivot after a bad IP is identified |
| BRIN on `occurred_at`, per partition | time-range scans at scale |

`evidence.events` is range-partitioned monthly on `occurred_at`. Forensic queries
are overwhelmingly time-bounded, so pruning removes most of the table before the
plan starts, and retention becomes `DROP TABLE` rather than a mass `DELETE` and
the vacuum storm that follows.

Storage is effectively exactly-once on top of at-least-once delivery: the fact
insert is `ON CONFLICT (event_id, occurred_at) DO NOTHING`, so a redelivered
event is a no-op. Verified by replaying a full batch and asserting the row count
does not move.

---

## Detection (Phase 3)

```
raw message ──► Drain template ──► log key ──► LogBERT ──► calibrated threshold
                (14 templates)    (template,    (69k params)   (benign holdout)
                                   outcome)
```

**Template mining.** Drain (He et al., 2017) collapses 20,000 raw messages into
**14 templates**. Depth is 3, not the paper's 4, and that was measured rather
than guessed: `sudo: <user> : N incorrect password attempts` puts the username
in the *second* token, which at depth 4 becomes a tree branch — one log type
shatters into 13 template ids, and a user unseen during training produces an
unknown token so ordinary activity looks novel.

| depth | templates | `sudo` templates | unmatched on held-out users |
|---|---|---|---|
| 3 | 14 | 1 | **0.0%** |
| 4 | 27 | 13 | 0.4% |

**The log key is `(template_id, outcome)`, not the template alone.** Drain's
similarity is position-wise and blind to which token carries meaning: `Failed
password` and `Accepted password` differ in one token out of eleven, so it
merges them — and the merge is sticky, surviving thresholds 0.5, 0.6 and 0.7.
That erases exactly the distinction a brute-force detector needs. Normalisation
already produced a structured `outcome` field, so folding it into the key
restores the signal instead of fighting the parser.

**One-class training.** The model sees benign traffic only; `train()` raises if
handed a window labelled anomalous. This is not a convenience — real estates
have no labelled attacks, novel tradecraft is by definition absent from any
label set, and a 1-in-10,000 class imbalance makes supervised training hopeless.
Synthetic labels exist solely to *measure* the detector.

**Two objectives.** Masked log-key prediction (learn the distribution of normal
continuations) plus LogBERT's hypersphere term (pull sequence representations
toward a learned centre). MLM alone can be satisfied by memorising local
bigrams; the sphere term forces a global notion of normal and supplies a second,
independent signal. The centre is a buffer fixed from data after a two-epoch
warmup, never a learned parameter — gradient descent would collapse the encoder
to a constant and drive the radius to zero.

**Four scoring signals, because they fail differently:**

| signal | catches | why it exists |
|---|---|---|
| `max_nll` | one impossible event in an ordinary window | a 2-event exfiltration chain is 12% of a 16-event window; any average dilutes it below threshold |
| `mean_nll` | sustained surprise | a 40-event brute-force burst |
| `sphere_distance` | globally unusual sessions | independent of local transitions |
| `miss_ratio` | *(reported, not used)* | LogBERT's published top-*g* rule |

The published top-*g* rule was implemented first and measured: with ~2 bits of
irreducible entropy in the benign baseline, benign windows miss top-3 routinely,
the threshold calibrated to **1.000**, and recall collapsed to 0.003. Switching
to likelihood-based scoring took F1 from 0.006 to 0.83. The rule is kept and
reported for comparison, not used for decisions.

**Thresholds are calibrated on a benign-only holdout** to a target false-positive
rate. An operations team can state the alert budget it can absorb; nobody can
state in advance what miss ratio counts as "high".

### Results

Three disjoint datasets with different seeds *and* different host/user
populations. Train and calibration are benign-only; test is touched once.

```
LogBERT       precision=0.853  recall=0.794  f1=0.833  pr_auc=0.837
UNK baseline  precision=1.000  recall=0.245  f1=0.393  pr_auc=0.342
```

| scenario | LogBERT | "unseen template" rule |
|---|---|---|
| c2_beaconing | 1.000 | 1.000 |
| ssh_brute_force_success | 1.000 | 1.000 |
| reverse_shell | 0.946 | 0.929 |
| privilege_escalation | 0.846 | 0.808 |
| **ssh_brute_force** | **0.794** | **0.043** |
| data_exfiltration | 0.500 | 0.412 |

That last-but-one row is the whole justification for the model. Brute force uses
**only templates the model already knows** — the anomaly is the *sequence*, not
the vocabulary — so the trivial rule is blind to it (0.043) while the
transformer catches it (0.794). On scenarios that introduce novel commands the
one-line rule is nearly as good, and it is reported alongside rather than
quietly omitted.

### A generator flaw this exposed

The first trained model plateaued at 44% MLM accuracy against a 40% majority
class. Rather than tune, I measured the data: **mutual information between
consecutive log keys was 0.0009 bits.** The benign stream was i.i.d. by
construction — there was nothing sequential to learn, and a sequence model on it
is meaningless.

The fix was in the generator, not the model. Real hosts emit correlated
sessions: a login is followed by a shell, then commands, then a logout; cron
runs a fixed chain; a web request triggers a database call. Adding those
sessions raised mutual information to **0.325 bits**, and detection followed.
A benign periodic monitoring heartbeat is included deliberately as a hard
negative — without it "regular interval plus uniform payload" would perfectly
separate C2 beaconing, and the detector would be learning an artefact of the
simulation rather than anything transferable.

---

## Evidence ledger (Phase 4)

```
INSERT evidence.events
        │  (same transaction, statement-level trigger)
        ▼
ledger.event_digests        SHA-256(0x00 ‖ canonical_form)
        │  (periodic sealing, single-writer)
        ▼
ledger.chain_blocks         Merkle root ──► block_hash = SHA-256(0x02 ‖ prev ‖ root ‖ seq:count)
        └────────────────── prev_hash ◄── previous block
```

**Why blocks rather than a per-row chain.** The obvious design — each row's hash
covering the previous row's — needs a strict total order over inserts, which
means serialising every write behind a lock on the chain head. That would turn
the bulk path into a single-writer queue. Splitting it in two avoids the trade: per-event digests depend only on the row's own content, so
they need no ordering and no lock, and the chain is built afterwards by a
single-writer sealer.

**What each layer catches:**

| Tamper | Caught by | Finding |
|---|---|---|
| Edit an event | recomputed digest ≠ stored | `event_modified` |
| Edit event **and** its digest | Merkle root sealed over the original | `merkle_root_mismatch` |
| Delete an event | orphaned digest | `event_deleted` |
| Delete a digest | event has none; block count disagrees | `event_undigested`, `event_count_mismatch` |
| Edit a block | block hash covers its own contents | `block_hash_mismatch` |
| Remove a block | dense sequence, linked hashes | `sequence_gap`, `broken_link` |

The second row is the one that matters. A single-layer design is defeated by an
attacker who updates the row and recomputes its digest; the block's Merkle root
was sealed over the *original* digest, so it objects anyway. Every row above is
an executed test in `tests/db/test_ledger.py`.

**The honest gap.** Between insert and the next seal, an event is digested but
unchained — and there, a coordinated edit to both row and digest *would* go
undetected. `LEDGER_SEAL_INTERVAL_SECONDS` bounds that window, which makes it a
security parameter rather than a performance knob, and `ledger.chain_status`
reports the current unsealed count on every sealer cycle.

### Verified twice, independently

The hashing protocol is implemented **both** in SQL and in Python, and a test
asserts they agree byte for byte on real data (3,000 events: canonical forms,
digests, Merkle roots, block hashes — all identical).

That duplication is the point. A ledger checked only by the database that stores
it proves very little: an attacker able to rewrite evidence rows can usually
rewrite `ledger.verify_chain()` too. `scripts/verify_ledger.py` recomputes
everything from raw column values, calls none of the `ledger.*` SQL functions,
and exits non-zero on any finding:

```console
$ python scripts/verify_ledger.py
INTACT — 20000 events, 5 blocks, 0 unsealed
```

### Cryptographic details

* **Length-prefixed canonical form.** `message` is attacker-influenced text, so a
  delimiter-separated encoding is forgeable — a crafted log line containing the
  delimiter could shift field boundaries and make two different records share a
  canonical form. Each field is prefixed with its **byte** length (a multibyte
  character must not change the framing), and `NULL` encodes as length `-1`, so
  it stays distinct from the empty string.
* **Domain separation** (RFC 6962 style): leaves are hashed under `0x00`,
  internal nodes under `0x01`, blocks under `0x02`. Without it an internal node
  could be presented as a leaf — the classic Merkle second-preimage attack.
* **Odd nodes are promoted, never duplicated.** Bitcoin's construction
  duplicates a lone odd node, which lets `[a,b,c]` and `[a,b,c,c]` produce an
  identical root (CVE-2012-2459) — a forged block that verifies. There is a
  regression test.
* **Sequence and count are delimited** inside the block hash, so `(seq=1,
  count=23)` cannot collide with `(seq=12, count=3)`.

### Inclusion proofs

A Merkle tree rather than a flat block hash buys one thing: a single event can
be proved to belong to a sealed block by disclosing O(log n) sibling hashes and
**nothing else in the block**. That matters when evidence goes to a third party
entitled to one record and not the rest.

```console
$ python scripts/verify_ledger.py --prove 36564470-cd8a-4a33-92d3-8ec418934934
block        #1
leaf digest  96499273d1f25e8c82dd679607252caf33186c6806e99a88d82ffa70aea643a3
merkle root  a0d5bcaac9c8917776683fbac4812198b2b4ee388a4f3f678955b48795ef105d
proof        12 sibling hashes
...
verified: YES
```

12 hashes prove one event out of 4,000. A tampered digest against the same proof
verifies `NO`.

**Append-only is enforced by grant, not convention.** `forensics_app` holds
`SELECT, INSERT` on the `ledger` schema and no `UPDATE` or `DELETE` — a chain
its writer can rewrite is not tamper-evident. A test reads
`information_schema.role_table_grants` to confirm that is actually in place.

**Cost**, measured on the same 50,000 events with the trigger disabled and then
enabled: **12,400 → 8,200 rows/s, about 34%**. Sealing 50,000 events into 10
blocks takes ~0.3s; full out-of-database verification of all 50,000 takes ~1.0s.
(Laptop measurements, and noisy — one baseline run dropped to 1,800 rows/s when
autovacuum ran. The paired figures above are the best of two runs each.)

A one-byte change 25,000 events deep, caught in a second:

```console
$ python scripts/verify_ledger.py
COMPROMISED (1 findings) — 50000 events, 10 blocks, 0 unsealed
  event_modified event 3b2b3239-…: recomputed bf0f494df13a8819… but ledger holds 9643cc55379d1b99…
```

---

## Production-readiness notes

**Structured logging.** One JSON object per line on stdout, with caller fields
promoted to top-level keys and a per-run `correlation_id`. In dry-run the logs
move to stderr so stdout stays a clean data stream.

**Delivery guarantees.** `acks=all` plus `enable.idempotence=true` gives ordered,
duplicate-free writes per partition. Both default safely even if the environment
is empty — a test asserts this, because a silently degraded `acks=1` is exactly
the kind of regression that only shows up as missing evidence.

**Two different dead-letter paths**, because they are different failure domains:

| Failure | Mechanism | Why |
|---|---|---|
| Broker unreachable (producer side) | append-only JSONL **spool file** on a volume | you cannot dead-letter *to* Kafka when Kafka is the thing that is down |
| Unparseable record (consumer side, Phase 2) | `logs.raw.dlq` **topic**, 30-day retention | the record is deliverable; only its content is bad |

Backpressure is handled rather than dropped: a full local queue triggers
`poll()` + exponential backoff, and only genuinely undeliverable records reach
the spool.

**Graceful shutdown.** SIGTERM/SIGINT set a flag, the loop exits through
`sink.close()`, and Compose allows a 30 s grace period — killing a producer
mid-batch is how you lose the records still sitting in librdkafka's queue.

**Rate limiting** uses absolute deadlines rather than `sleep(1/rate)`, which
would accumulate drift; measured output holds 499.98 ev/s against a 500 target.
After a stall it resynchronises instead of emitting an unbounded catch-up burst.

**Least privilege.** Containers run as uid 10001, and the database's
`forensics_app` role gets `SELECT/INSERT` on the ledger schema and no DDL
rights — evidence integrity depends on the writer being unable to rewrite it.

**Determinism.** `PRODUCER_SEED` makes a run byte-reproducible (ids embedded in
messages come from the seeded RNG, not `uuid4`), so a training set can be
regenerated exactly.

---

## Configuration

Every knob is an environment variable; see [.env.example](.env.example) for the
full annotated list. Invalid values fail fast at startup with the variable name
in the message rather than surfacing later as a confusing `TypeError`.

| Variable | Default | Purpose |
|---|---|---|
| `PRODUCER_EVENTS_PER_SECOND` | `25` | Emission rate |
| `PRODUCER_ANOMALY_RATE` | `0.03` | Target malicious **event** fraction |
| `PRODUCER_MAX_EVENTS` | `0` | `0` = run until stopped |
| `PRODUCER_SEED` | *(unset)* | Set for a reproducible stream |
| `PRODUCER_DRY_RUN` | `false` | Print to stdout instead of publishing |
| `KAFKA_ACKS` | `all` | Durability |
| `LOG_LEVEL` | `INFO` | Log verbosity |

---

## Testing

```bash
make check        # ruff + mypy + core suite (no infrastructure)
make test-model   # 50 detector tests (needs torch)
make test-spark   # 43 Spark tests    (needs make venv-spark + JDK 17/21)
make test-db      # 42 database tests (needs a live PostgreSQL)
make test-all     # everything
```

**270 tests in four suites**, split by what infrastructure they need so the
default `make test` stays runnable on a laptop with nothing installed.

| Suite | Tests | Requires |
|---|---|---|
| core | 135 | nothing |
| `tests/model` | 50 | PyTorch |
| `tests/spark` | 43 | a JVM (JDK 17 or 21) |
| `tests/db` | 42 | live PostgreSQL — **destructive, it truncates evidence** |

They assert the properties later phases depend on, not just line coverage:

* **Core (51)** — campaign events stay contiguous and ordered; beacon intervals
  keep their low variance; the anomaly ratio converges to its target; no
  routable public IP is ever emitted; Kafka durability cannot silently degrade.
* **Spark (43)** — the declared schema does not drift from the producer's
  dataclasses; every validation failure reports its own specific reason; DLQ
  records preserve the payload byte-for-byte; evaluation labels never reach a
  feature frame (and the guard itself is tested); windows are actually emitted
  once the watermark passes, late data is dropped, and a query restarted from a
  checkpoint neither replays nor loses rows.
* **Detector (49)** — templates do not fragment on an early variable token and
  held-out users still match; a frozen vocabulary returns UNK instead of
  growing; padding cannot change a pooled representation; random MLM
  replacements are never reserved ids; training *refuses* labelled attack data;
  a saved bundle reloads to identical scores; calibration honours its budget;
  and the model must beat the trivial UNK rule on PR-AUC.
* **Database (42)** — dimensions deduplicate; replay is idempotent; no orphaned
  foreign keys; ground truth is structurally confined to `analytics`; identity
  sequences are not burned by upserts; the planner can use the indexes; SQL and
  Python agree byte for byte on every digest; and each of the six tamper
  scenarios above is actually detected.
* **Ledger protocol (48, in core)** — a delimiter inside a field cannot forge a
  boundary; `NULL` ≠ empty string; every canonical field is covered by the
  digest; odd Merkle nodes are promoted not duplicated (CVE-2012-2459); every
  leaf can prove its own inclusion; and a flipped sibling side, forged sibling or
  wrong root all fail.

`make test-spark` needs Java 17 or 21. Java 24 removed the Security Manager APIs
(JEP 486) that Hadoop still calls, so Spark 4.0 fails there with
`getSubject is not supported` — `scripts/find-java.sh` picks a working JDK and
verifies the version it is handed, because `/usr/libexec/java_home -v 21` will
happily return a JDK 25.

## Troubleshooting

Every item here is a failure actually hit while bringing the stack up, with the
cause rather than just the symptom.

**`dependency failed to start: container forensics-kafka is unhealthy`**
Kafka logs `advertised.listeners cannot use the nonroutable meta-address
0.0.0.0`. A controller listener is deliberately absent from
`advertised.listeners`, so Kafka derives its advertised address from `listeners`
— and rejects `0.0.0.0`. Bind with an empty host (`CONTROLLER://:9093`), which
resolves to the canonical hostname. Already fixed in `docker-compose.yml`.

**Spark crash-loops with `module 'datetime' has no attribute 'UTC'`**
`datetime.UTC` is Python 3.11+, but `apache/spark:4.0.0-python3` ships **Python
3.10**. Ruff's `target-version` must match the *lowest* interpreter any service
runs, or it will happily modernise code into something the runtime cannot
execute. Pinned to `py310` in `pyproject.toml`.

**`mkdir of file:/var/lib/spark/checkpoints/... failed`**
Docker seeds a named volume from whatever the image has at the mount path,
ownership included — and the base image's directory is `root:root` while the
container runs as uid 185. The directory is created and chowned in
`docker/Dockerfile.spark`.

**`Failed to create a temp directory (under artifacts) after 10 attempts!`**
Spark 4.0's ArtifactManager creates scratch space *relative to the working
directory*. A root-owned `WORKDIR` fails here, after the session is already up,
which makes it look like a Spark bug. `WORKDIR` is the base image's writable
`work-dir`.

**`evidence.events` stays empty while `evidence.raw_events` grows**
Nothing is calling `evidence.normalize_raw_events()`. The `sealer` service owns
that (`LEDGER_NORMALIZE_ENABLED=true`); check it is running, or run
`make normalize` by hand.

**The scorer exits with `Model bundle has no calibrated thresholds`**
The bundle was written without its calibration. Retrain with `make train` —
`save_bundle()` now requires the threshold, so this cannot recur.

**Spark tests skip, or fail with `getSubject is not supported`**
Java 24+ removed the Security Manager APIs Hadoop still calls. Spark 4.0 needs
JDK 17 or 21, and `/usr/libexec/java_home -v 21` may return a newer JDK anyway.
Use `export JAVA_HOME=$(./scripts/find-java.sh)`, which verifies the version.

**`PYTHON_VERSION_MISMATCH` from PySpark**
Driver and workers must share a Python *minor* version. Set `PYSPARK_PYTHON` and
`PYSPARK_DRIVER_PYTHON` to the same interpreter.

**`refusing to run: these applied migrations have been edited`**
The migration runner's checksum drift detection, working as intended —
migrations are immutable once applied. Add a new one, or recreate the database
in local development.

**`make test-db` wiped my data**
It truncates `evidence.*`, `analytics.*` and `ledger.*`. Point `POSTGRES_DB` at
a throwaway database; the target now confirms before running.

---

## Known gaps

Stated plainly, because a reviewer will find them anyway:

- **Detection metrics come from synthetic data** with a known generator. Real
  logs are messier, and the numbers would not transfer unchanged.
- **The producer's dead-letter spool is written but never drained.** A replay
  job is the obvious next piece.
- **Alerts are stored, not acted on.** `analytics.detections` and
  `alerts.anomalies` are populated; nothing triages or notifies.
- **Single-node everything.** Replication factor 1, one Kafka broker, one Spark
  driver. The partitioning and keying choices are made *for* horizontal scale,
  but scale-out is untested.
- **The inference image logs `Failed to initialize NumPy`.** Harmless today —
  the scorer works — but any `.numpy()` call would fail.
- **The unsealed window is real.** Between insert and seal, a coordinated edit to
  both an event and its digest would go undetected.
  `LEDGER_SEAL_INTERVAL_SECONDS` bounds it; `ledger.chain_status` reports it.

---

## Design decisions

See [docs/architecture.md](docs/architecture.md) for the reasoning behind KRaft
over ZooKeeper, ECS over a bespoke schema, host-based partition keying, and the
split dead-letter strategy.
