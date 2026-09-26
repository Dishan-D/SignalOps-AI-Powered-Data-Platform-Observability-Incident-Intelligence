"""Evidence persistence tier — tamper-evident append-only ledger.

Two layers, because a single-layer design forces a bad trade:

* **Per-event digests** are written by a statement-level trigger in the same
  transaction as the event, so no committed evidence can exist unhashed. They
  depend only on the row's own content, so no ordering and no lock is needed.
* **Merkle-rooted blocks** chain those digests. Sealing is a separate,
  single-writer operation, which keeps the bulk ingest path unserialised.

A naive per-row chain (each row's hash covering the previous row's) would need a
strict total order over inserts, turning bulk ingestion into a single-writer
queue. The digest trigger alone costs ~34% (12,400 -> 8,200 rows/s on the same
50,000 events, trigger disabled then enabled); a serialised chain would be far
worse.

The application role holds ``SELECT, INSERT`` and no ``UPDATE`` or ``DELETE`` on
this schema — a chain its writer can rewrite is not tamper-evident.

See :mod:`forensics.ledger.chain` for the hashing protocol and
:mod:`forensics.ledger.verifier` for out-of-database verification.
"""

from forensics.ledger.chain import (
    Finding,
    VerificationReport,
    block_hash,
    canonical_event,
    event_digest,
    genesis_hash,
    merkle_root,
    verify_inclusion,
)

__all__ = [
    "Finding",
    "VerificationReport",
    "block_hash",
    "canonical_event",
    "event_digest",
    "genesis_hash",
    "merkle_root",
    "verify_inclusion",
]
