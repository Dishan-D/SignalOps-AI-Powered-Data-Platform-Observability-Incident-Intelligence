# Architecture decisions

Short records of the choices that shape the rest of the build, and what each one
costs.

## 1. KRaft, not ZooKeeper

**Decision.** Kafka runs in KRaft mode — the controller quorum is embedded in
the broker, and there is no ZooKeeper container.

**Why.** ZooKeeper was deprecated in Kafka 3.5 and removed entirely in 4.0.
Adding it would mean introducing a dependency the project would have to unwind
later, plus a second stateful service to health-check and version-pin. KRaft
also starts faster, which matters for a stack people run on a laptop.

**Cost.** `CLUSTER_ID` becomes part of the on-disk format: changing it after
first start requires deleting the `kafka-data` volume. It is pinned in
`.env.example` and documented there.

## 2. ECS field names, not a bespoke schema

**Decision.** Events use Elastic Common Schema names (`host.name`,
`source.ip`, `event.category`, …) rather than a project-specific shape.

**Why.** ECS is what real telemetry sources emit. The synthetic producer is
scaffolding — it exists so the pipeline has data before real collectors are
wired in. If the schema matches what Filebeat/Auditbeat already produce, that
swap is a configuration change instead of a rewrite of every downstream
consumer. It also gives Phase 2 a stable contract and Phase 3 an obvious 3NF
decomposition, since host / user / process / network are already separate
nested objects.

**Cost.** ECS is more verbose than a minimal internal schema, and its nesting
means a flattening step in Spark.

## 3. Partition key = `host.name`

**Decision.** Every record is keyed by hostname.

**Why.** Kafka guarantees ordering only within a partition. Nearly every
detection in Phase 2/3 is a per-host stateful aggregation — failed-login bursts,
beacon interval variance, process ancestry — so keying by host makes those
partition-local. The alternative (random keys plus a shuffle) pays a network
cost on every window.

**Cost.** A single very noisy host creates a hot partition. At real scale the
key would become `host.name` plus a bucket suffix, at the price of merging
sub-streams during aggregation.

## 4. Two dead-letter mechanisms

**Decision.** Producer-side failures go to an append-only JSONL **spool file**
on a volume. Consumer-side parse failures (Phase 2) go to the
`logs.raw.dlq` **topic**.

**Why.** These look like one problem and are not. A producer's dominant failure
mode is *the broker is unreachable* — and a Kafka topic is precisely what you
cannot write to under that condition. Disk is the only durable thing left. A
consumer's dominant failure mode is a malformed record, which is perfectly
deliverable; that belongs on a topic with long retention where it can be
inspected and replayed. Conflating them means a broker outage silently discards
evidence.

**Cost.** Two paths to monitor, and the spool needs an operator (or a Phase 2
replay job) to drain it.

## 5. Anomaly rate is a closed loop

**Decision.** `PRODUCER_ANOMALY_RATE` is the target fraction of *events* that
are malicious, maintained by gating campaign starts on the ratio observed so
far.

**Why.** The obvious implementation — `rng.random() < anomaly_rate` per tick —
actually sets the probability of starting a *campaign*. Since one campaign emits
2–40 events, a configured 0.05 measured at **26%** in practice. Anyone reading
that config, or reporting a detector's base rate against it, would be wrong by
an order of magnitude.

**Cost.** Campaign onset is no longer an independent Bernoulli trial; a
separate constant controls clustering while the ratio gate controls the share.

## 6. Configuration is stdlib-only

**Decision.** `common/config.py` uses dataclasses and `os.environ`, not pydantic.

**Why.** Configuration is imported by every other module. Keeping it
dependency-free means the schema, the generators and the whole test suite run
without installing a native librdkafka wheel — which is also why the Kafka
import is lazy and why dry-run mode exists. 51 tests run in ~1.4 s with nothing
installed but pytest.

**Cost.** Hand-written coercion and validation helpers instead of a declarative
model. Bounded, and covered by tests.

## 7. Ledger writes are `INSERT`-only at the role level

**Decision.** The `forensics_app` role is granted `SELECT, INSERT` on the
`ledger` schema — no `UPDATE`, no `DELETE`, no DDL.

**Why.** A tamper-evident hash chain that the application can rewrite is not
tamper-evident. Enforcing append-only in the grant means a compromised
application credential still cannot quietly rewrite history; migrations run
separately as the schema owner.

**Cost.** Phase 4 must handle chain repair as a privileged, audited operation
rather than an ordinary write.

---

# Phase 2 decisions

## 8. Set-based ELT, not per-row normalisation

**Decision.** Spark appends flat rows to `evidence.raw_events`; a single
set-based SQL function resolves dimensions in bulk and inserts the facts.

**Why.** The first implementation was a PL/pgSQL loop calling a `resolve_*()`
function per dimension and `ensure_month_partition()` per row. Measured against
a 50,000-event load it managed **5 rows/s** — slower than the producer's default
25 events/s, so the backlog grew without bound. The set-based rewrite does one
statement per dimension per batch: **9,602 rows/s**, a ~1,900× improvement.

The same load exposed a second defect. `INSERT … ON CONFLICT DO UPDATE`
evaluates the column DEFAULT — and therefore `nextval()` — *before* it detects
the conflict. Upserting one of three dataset names once per event burned 32,767
identity values and overflowed a `SMALLINT` sequence, failing 29,233 of 50,000
rows. Dimension inserts are now guarded with `NOT EXISTS`, so `nextval()` is
only reached for genuinely new values, and the column was widened to `INTEGER`
because a narrow sequence is only safe while an assumption about cardinality
holds.

**Cost.** Per-row error isolation is weaker: a batch-level failure is attributed
to the batch rather than to one row. Rows that cannot produce a fact (null
event time) are marked with a reason and skipped instead.

## 9. The address dimension is keyed on IP, not (IP, port)

**Decision.** `evidence.network_addresses` holds distinct IP addresses. Ports
are columns on the fact table.

**Why.** Measured: with random ephemeral source ports, keying on `(ip, port)`
produced 4,039 dimension rows for 4,000 facts — a dimension with roughly one row
per fact, costing two joins and compressing nothing. The same data holds 1,361
distinct addresses. The modelling error was normalising on something that is not
an entity: an address persists, recurs, and is what threat intelligence attaches
to; a port is an attribute of one flow.

**Cost.** Queries filtering on a specific `ip:port` pair use two predicates
instead of one surrogate key. Cheap, and both columns are indexed.

## 10. Ground truth is carried, isolated, and asserted

**Decision.** Synthetic labels survive normalisation in dedicated `eval_*`
columns, land in the `analytics` schema rather than `evidence`, and are checked
out of every feature frame by `assert_no_label_leakage()`.

**Why.** Dropping labels entirely would make Phase 3 unmeasurable — there would
be no way to compute precision or recall. Keeping them *in* the feature vector
would let the model read the answer off its own input, the single most damaging
bug available in an ML pipeline. Carrying them in a separate schema makes "never
train on the labels" a structural property rather than a naming convention
someone has to remember, and the runtime guard is itself covered by a test that
proves it fires.

**Cost.** One more column set to thread through the transform.

## 11. Connector JARs are baked into the image

**Decision.** `docker/Dockerfile.spark` downloads the Kafka connector, its
transitive dependencies and the Postgres JDBC driver at build time, pinned by
version, instead of resolving `--packages` at startup.

**Why.** Runtime resolution reaches out to Maven Central on every container
start: slow, broken on an air-gapped or rate-limited network, and it silently
changes what you are running if a version moves. Versions match the connector's
declared transitive dependencies for Spark 4.0.0 / Scala 2.13
(`kafka-clients` 3.9.0, `commons-pool2` 2.12.0), verified against the published
POM rather than guessed.

**Cost.** A dependency bump is a rebuild, and the version list must be kept in
step with the Spark version.

## 12. Two feature grains, two window lengths

**Decision.** Host-activity features use a 1-minute sliding window;
peer-connection features use 10 minutes.

**Why.** A C2 beacon on a 300-second interval produces zero samples inside a
one-minute window, so no amount of tuning would let the host-grain stream see
periodicity — the grain and the window are wrong for that signal, not the
threshold. Beaconing is also low-volume by design, so it is invisible in
host-level aggregates. Sliding rather than tumbling windows matter for the same
class of reason: a burst straddling a tumbling boundary is halved and can fall
under threshold on both sides.

**Cost.** Two stateful aggregations to keep in state, and results arrive one
watermark-delay after the window closes.

---

# Phase 3 decisions

## 13. Drain depth 3, and a composite log key

**Decision.** Template mining runs at depth 3 (the paper says 4), and the
model's token is `(template_id, outcome)` rather than the template id alone.

**Why.** Both were measured, not assumed.

Depth: `sudo: <user> : N incorrect password attempts` places the username in the
second token. At depth 4 that token is a tree branch, so every user gets a
private subtree and one log type shatters into 13 template ids; 0.4% of a
held-out stream with unfamiliar users failed to match at all. At depth 3 the
tree branches on the daemon name only, similarity matching generalises the
username to `<*>`, and held-out matching is complete.

Composite key: Drain's similarity is position-wise and semantically blind.
`Failed password` and `Accepted password` differ in one token of eleven, so they
merge — and because the merge generalises that position to `<*>`, every later
message matches it too. Raising the threshold to 0.6 and 0.7 did not undo it;
only a threshold high enough to shatter every other template would. Since
normalisation already produced a structured `outcome`, folding it into the key
recovers the distinction for one extra dimension of vocabulary.

**Cost.** The key now depends on two tiers agreeing: a change to how `outcome`
is normalised invalidates a trained vocabulary.

## 14. Likelihood scoring, not the published top-*g* rule

**Decision.** Decisions use `max_nll`, `mean_nll` and `sphere_distance`.
LogBERT's top-*g* miss ratio is computed and reported but does not decide.

**Why.** The published rule was implemented first and failed here, for a reason
specific to this data: the benign baseline carries ~2 bits of irreducible
entropy (~4 effective continuations), so benign windows miss a top-3 test
routinely. Calibration drove the miss-ratio cut to **1.000** and recall
collapsed to 0.003. Negative log-likelihood uses the whole distribution and
degrades gracefully in that regime — F1 went from 0.006 to 0.83.

`max_nll` exists specifically because averaging hides short attacks: a two-event
exfiltration chain is 12% of a sixteen-event window, and mean-based scoring gave
it recall 0.13.

**Cost.** A departure from the reference implementation, which has to be
explained — hence reporting the original statistic alongside.

## 15. The benign generator needed sessions before any of this worked

**Decision.** Benign traffic is emitted as correlated sessions (login → shell →
commands → logout; cron chains; request → app → database), not independent
events.

**Why.** The first trained model sat at 44% MLM accuracy against a 40% majority
class. Measuring the data rather than tuning the model found the cause: mutual
information between consecutive log keys was **0.0009 bits**. The stream was
i.i.d. by construction, so there was no sequential structure for a sequence
model to learn and no amount of architecture would have helped. Sessions raised
it to **0.325 bits**.

A benign periodic monitoring heartbeat is included on purpose. Without one,
"regular interval, uniform payload" separates C2 beaconing perfectly, and the
detector would be learning an artefact of the simulator rather than a property
of beacons.

**Cost.** The generator is more complex, and its session mix is now a modelling
assumption that shapes what the detector finds easy.

## 16. Detections live in `analytics`, never in `evidence`

**Decision.** Verdicts, model runs and mined templates are all in the
`analytics` schema. `evidence` holds only what was observed.

**Why.** A detection is an *opinion* about evidence, produced by a specific
model version and revisable when a better model arrives. Evidence is a record
sealed by the Phase 4 hash chain. If re-scoring history mutated rows inside
`evidence`, every re-run would invalidate the chain — the integrity guarantee
and the ability to improve the model would be in direct conflict.

Each detection stores its raw per-signal values and the thresholds in force, so
"why did this fire?" is answerable and a threshold change is re-evaluable
without re-running the model.

**Cost.** Evaluation needs a join (`analytics.detection_truth` provides it).

## 17. The trivial baseline is reported alongside the model

**Decision.** Every evaluation reports an "unseen log template" rule next to the
detector, and a test fails if the model does not beat it on PR-AUC.

**Why.** Novel tradecraft produces novel templates, so on synthetic data a
one-line rule is a genuinely strong detector — it reaches F1 0.39 here. A model
that cannot beat it is not earning its complexity, and publishing only the
model's own numbers would hide that. The comparison also localises where the
transformer actually helps: brute force uses only known templates, so the rule
scores 0.043 and the model 0.794.

**Cost.** None worth mentioning; it is a few lines of evaluation code.

---

# Phase 4 decisions

## 18. Two-layer integrity, not a per-row hash chain

**Decision.** Per-event digests are written by a statement-level trigger in the
same transaction as the insert. Merkle-rooted blocks chain those digests, sealed
separately by a single-writer service.

**Why.** The textbook design — each row's hash covering the previous row's —
requires a strict total order over inserts. Enforcing it means serialising every
write behind a lock on the chain head, which would turn the bulk path into a
single-writer queue. Splitting the problem removes the trade:
a per-event digest depends only on its own row, so it needs no ordering and no
lock, while the chain is built afterwards without touching the ingest path.

The statement-level trigger matters too. The bulk path inserts thousands of rows
per statement; a per-row PL/pgSQL trigger on that is the difference between a
set-based `INSERT … SELECT` and a loop. PostgreSQL 17 supports transition tables
on partitioned tables, which is what makes it possible.

**Cost.** ~34% on bulk normalisation — 12,400 → 8,200 rows/s, measured on the
same 50,000 events with the trigger disabled and then enabled — and a window
between insert and seal in which a *coordinated* edit to both row and digest
would go undetected. `LEDGER_SEAL_INTERVAL_SECONDS` bounds it and
`ledger.chain_status` reports it, but it is real and is documented as such
rather than glossed over.

## 19. The protocol is implemented twice, on purpose

**Decision.** Canonical serialisation, digests, Merkle roots and block hashing
exist as both SQL functions and Python (`forensics.ledger.chain`). A test
asserts they agree byte for byte on real data.

**Why.** A ledger verified only by the database that stores it proves very
little: an attacker who can rewrite `evidence.events` can usually also rewrite
`ledger.verify_chain()`. `scripts/verify_ledger.py` treats the database as an
untrusted store of bytes — it reads raw column values and calls none of the
`ledger.*` functions.

Duplication normally invites drift. Here the cross-check test converts that risk
into a build failure, and it earned its keep immediately: it caught a
`row_number() OVER ()` in the SQL inclusion-proof builder, where the window was
evaluated *before* the outer `ORDER BY`, so the leaf index did not match its
position in the tree and every proof was built along the wrong path.

**Cost.** Two implementations to keep in step, and the field order is now a
frozen protocol — changing it invalidates every digest ever written.

## 20. Merkle trees, for inclusion proofs

**Decision.** Blocks carry a Merkle root rather than a flat hash over their
events, and `ledger.inclusion_proof()` returns the sibling path.

**Why.** A flat hash proves the block is intact but says nothing about one event
without disclosing all of them. A Merkle path proves a single record belongs to
a sealed block using O(log n) hashes and reveals no other record — 12 hashes for
one event out of 4,000. That is the difference between handing a third party one
piece of evidence and handing them the whole block.

Two details are security-relevant, not stylistic:

* **Domain separation** (RFC 6962): leaves under `0x00`, internal nodes under
  `0x01`, blocks under `0x02`. Without it an internal node hash could be
  presented as a leaf — the classic Merkle second-preimage attack.
* **Odd nodes are promoted unchanged, never duplicated.** Bitcoin duplicates the
  lone node, which lets `[a,b,c]` and `[a,b,c,c]` produce the same root
  (CVE-2012-2459) — a forged block that verifies.

**Cost.** More code than a flat hash, and proof generation is O(n) in block size
because the tree is rebuilt rather than stored.

## 21. Append-only is a grant, not a convention

**Decision.** `forensics_app` has `SELECT, INSERT` on `ledger` and no `UPDATE`
or `DELETE`. Blocks are written by `ledger.seal_block()`, which runs as the
owner.

**Why.** A chain its own writer can rewrite is not tamper-evident. Enforcing it
in the grant means a compromised application credential still cannot quietly
rewrite history — the attacker needs the schema owner, which is a different and
more visible escalation. A test reads `information_schema.role_table_grants` to
confirm the grant is actually in place rather than merely intended.

**Cost.** Chain repair (after a legitimate restore, say) is a privileged,
audited operation rather than an ordinary write — which is the correct shape for
it, but does mean it cannot be automated behind the application's own
credentials.
