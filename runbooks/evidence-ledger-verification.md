# Evidence Ledger Verification

## Purpose

Interpret the tamper-evident ledger's status and respond to sealing delays and
verification failures. Every event inserted into `evidence.events` gets a
SHA-256 digest in the same transaction; the sealer chains batches of digests
into Merkle-rooted blocks; an out-of-database verifier recomputes everything
from raw column values.

## Symptoms

- `ledger` component `unhealthy` (latest verification found findings) or
  `degraded` (sealing stalled or verification stale).
- `ledger_integrity` (critical) or `ledger_seal_stalled` incident candidates.
- `unsealed_events` growing on `/api/ops/ledger/status`.

## Evidence to collect

1. `get_ledger_status`: block count, head sequence and hash, unsealed events,
   seconds since the last seal, latest verification and its findings.
2. Sealer logs: `docker compose logs sealer` ("Maintenance cycle complete",
   "LEDGER INTEGRITY FAILURE").
3. An on-demand verification from outside the database: `make ledger-verify`.

## Diagnostic steps

1. **Findings present?** Read the finding kinds:
   - `event_modified` — an event row no longer hashes to its stored digest:
     the row was changed after insert.
   - `event_undigested` — an event exists with no digest (inserted around the
     trigger, or its digest was removed).
   - `event_deleted` — a digest remains whose event row is gone.
   - `merkle_root_mismatch` / `event_count_mismatch` — a sealed block's contents
     no longer match its recorded root or size.
   - `block_hash_mismatch` / `broken_link` / `sequence_gap` — the chain itself
     was altered: blocks rewritten, removed, reordered or inserted.
2. **Sealing stalled?** If `unsealed_events` grows and no seal is recent, check
   that the sealer container is running and that its cycles are not failing.
3. **Verification stale?** The sealer verifies every `LEDGER_VERIFY_EVERY_CYCLES`
   cycles. Run `make ledger-verify` to obtain a fresh result.

## Expected observations

- Healthy: latest verification intact, unsealed events below one seal batch, last
  seal within roughly `LEDGER_SEAL_INTERVAL_SECONDS`.
- Sealer down: unsealed events grow linearly with ingest; verification ages out.
- Tampering: findings name specific events or blocks; they do not clear on their own.

## Possible causes

- Deliberate or accidental modification of evidence rows or ledger tables.
- Sealer stopped, crash-looping, or unable to reach Postgres.
- Restore from a backup that did not include the ledger schema consistently.

## Recommended next steps

- For findings: **stop**. Preserve the database state (snapshot the volume),
  record the findings, and escalate. Do not "repair" digests or blocks.
- For stalled sealing: restore the sealer, then confirm unsealed events fall and a
  new block appears (`make ledger-status`).
- After recovery, run `make ledger-verify` and attach its output to the incident.

## Escalation criteria

- Any integrity finding: escalate immediately to the evidence owner and security.
- Sealing stalled beyond 15 minutes: the undetectable-edit window is growing.

## Limitations and safety

- Events between insert and the next seal are digested but not chained; a
  coordinated edit to both a row and its digest in that window is not detectable.
- The ledger shows that sealed records have not changed; it does not show that a
  record was accurate when written.
- The investigation agent and the API are read-only; integrity can be checked
  but never modified through SignalOps.
