"""Out-of-database ledger verification.

Reads raw column values and recomputes everything in Python — digests, Merkle
roots, block hashes, the chain. It calls none of the ``ledger.*`` SQL functions,
because an attacker able to rewrite evidence rows can usually also rewrite the
functions that check them. The database is treated here as an untrusted store of
bytes.

Rows are streamed with a server-side cursor rather than loaded at once: a
forensic store is expected to outgrow memory, and a verifier that OOMs on a
large table is a verifier nobody runs.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from forensics.common.logging import get_logger
from forensics.ledger.chain import (
    EVENT_FIELDS,
    Finding,
    VerificationReport,
    block_hash,
    event_digest,
    genesis_hash,
    merkle_root,
)

logger = get_logger(__name__, component="ledger-verifier")

#: Rows per round trip while streaming evidence.
FETCH_SIZE = 2_000


def _event_rows(connection: Any) -> Iterator[dict[str, Any]]:
    """Stream evidence rows joined to their stored digests."""
    columns = ", ".join(f"e.{name}" for name in EVENT_FIELDS)
    # A named (server-side) cursor keeps the result set on the server, but
    # DECLARE CURSOR is only legal inside a transaction — and callers routinely
    # hand us an autocommit connection.
    with connection.transaction(), connection.cursor(name="ledger_verify_events") as cur:
        cur.itersize = FETCH_SIZE
        cur.execute(
            f"""
            SELECT {columns}, d.digest
              FROM evidence.events e
              LEFT JOIN ledger.event_digests d
                ON d.event_id = e.event_id AND d.occurred_at = e.occurred_at
             ORDER BY e.occurred_at, e.event_id
            """
        )
        for row in cur:
            record = dict(zip(EVENT_FIELDS, row[: len(EVENT_FIELDS)], strict=True))
            record["_digest"] = row[len(EVENT_FIELDS)]
            yield record


def verify_events(connection: Any) -> tuple[int, list[Finding]]:
    """Layer 1: every event must still hash to its stored digest."""
    findings: list[Finding] = []
    checked = 0

    for row in _event_rows(connection):
        checked += 1
        stored = row.pop("_digest")

        if stored is None:
            findings.append(
                Finding(
                    kind="event_undigested",
                    detail="event has no digest; the trigger was bypassed or the digest removed",
                    event_id=str(row["event_id"]),
                )
            )
            continue

        recomputed = event_digest(row)
        if recomputed != bytes(stored):
            findings.append(
                Finding(
                    kind="event_modified",
                    detail=(
                        f"recomputed {recomputed.hex()[:32]}… "
                        f"but ledger holds {bytes(stored).hex()[:32]}…"
                    ),
                    event_id=str(row["event_id"]),
                )
            )

    return checked, findings


def verify_deletions(connection: Any) -> list[Finding]:
    """A digest whose event is gone. Deletion cannot be silent."""
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT d.event_id
              FROM ledger.event_digests d
              LEFT JOIN evidence.events e
                ON e.event_id = d.event_id AND e.occurred_at = d.occurred_at
             WHERE e.event_id IS NULL
             LIMIT 1000
            """
        )
        return [
            Finding(
                kind="event_deleted",
                detail="digest exists but the evidence row is missing",
                event_id=str(row[0]),
            )
            for row in cur.fetchall()
        ]


def verify_chain(connection: Any) -> tuple[int, list[Finding]]:
    """Layers 2 and 3: Merkle roots, block hashes and linkage."""
    findings: list[Finding] = []
    expected_prev = genesis_hash()
    expected_sequence = 0
    blocks = 0

    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT block_id, sequence_number, prev_hash, merkle_root,
                   block_hash, event_count
              FROM ledger.chain_blocks
             ORDER BY sequence_number
            """
        )
        chain = cur.fetchall()

    for block_id, sequence, prev_hash, stored_root, stored_hash, event_count in chain:
        blocks += 1
        prev_hash = bytes(prev_hash)
        stored_root = bytes(stored_root)
        stored_hash = bytes(stored_hash)

        if sequence != expected_sequence:
            findings.append(
                Finding(
                    kind="sequence_gap",
                    detail=f"expected sequence {expected_sequence}",
                    sequence_number=sequence,
                )
            )
            expected_sequence = sequence

        if prev_hash != expected_prev:
            findings.append(
                Finding(
                    kind="broken_link",
                    detail=(
                        f"prev_hash {prev_hash.hex()[:32]}… does not match "
                        f"previous block {expected_prev.hex()[:32]}…"
                    ),
                    sequence_number=sequence,
                )
            )

        with connection.cursor() as cur:
            cur.execute(
                """
                SELECT digest FROM ledger.event_digests
                 WHERE block_id = %s
                 ORDER BY digested_at, event_id
                """,
                (block_id,),
            )
            leaves = [bytes(r[0]) for r in cur.fetchall()]

        if len(leaves) != event_count:
            findings.append(
                Finding(
                    kind="event_count_mismatch",
                    detail=(
                        f"block claims {event_count} events, "
                        f"{len(leaves)} digests reference it"
                    ),
                    sequence_number=sequence,
                )
            )

        recomputed_root = merkle_root(leaves)
        if recomputed_root != stored_root:
            findings.append(
                Finding(
                    kind="merkle_root_mismatch",
                    detail=(
                        f"recomputed {recomputed_root.hex()[:32]}… "
                        f"stored {stored_root.hex()[:32]}…"
                    ),
                    sequence_number=sequence,
                )
            )

        recomputed_hash = block_hash(prev_hash, stored_root, sequence, event_count)
        if recomputed_hash != stored_hash:
            findings.append(
                Finding(
                    kind="block_hash_mismatch",
                    detail=(
                        f"recomputed {recomputed_hash.hex()[:32]}… "
                        f"stored {stored_hash.hex()[:32]}…"
                    ),
                    sequence_number=sequence,
                )
            )

        expected_prev = stored_hash
        expected_sequence = sequence + 1

    return blocks, findings


def verify(connection: Any) -> VerificationReport:
    """Full verification. An empty findings list is the only clean result."""
    events_checked, findings = verify_events(connection)
    findings.extend(verify_deletions(connection))
    blocks_checked, chain_findings = verify_chain(connection)
    findings.extend(chain_findings)

    with connection.cursor() as cur:
        cur.execute("SELECT count(*) FROM ledger.event_digests WHERE block_id IS NULL")
        row = cur.fetchone()
        unsealed = int(row[0]) if row else 0

    report = VerificationReport(
        events_checked=events_checked,
        blocks_checked=blocks_checked,
        unsealed_events=unsealed,
        findings=findings,
    )
    logger.info(
        "Ledger verification complete",
        extra={
            "intact": report.intact,
            "events_checked": events_checked,
            "blocks_checked": blocks_checked,
            "unsealed_events": unsealed,
            "findings": len(findings),
        },
    )
    return report
