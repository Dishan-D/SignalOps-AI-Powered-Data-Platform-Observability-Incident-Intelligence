#!/usr/bin/env python3
"""Verify the evidence ledger from outside the database.

    python scripts/verify_ledger.py              # full verification
    python scripts/verify_ledger.py --seal       # seal pending events first
    python scripts/verify_ledger.py --json       # machine-readable report
    python scripts/verify_ledger.py --prove <event-id>   # inclusion proof

Exit codes are meant for a monitoring system:

    0  ledger intact
    1  findings — evidence has been altered
    2  could not run (configuration, connectivity)

Everything is recomputed in Python from raw column values. The ``ledger.*`` SQL
functions are deliberately not used: an attacker who can rewrite evidence rows
can usually rewrite the functions that check them too, so a verifier that asks
the database whether it has been tampered with proves very little.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

try:
    import psycopg
except ImportError:  # pragma: no cover - dependency guidance
    print("psycopg is required: pip install 'psycopg[binary]'", file=sys.stderr)
    raise SystemExit(2) from None

from forensics.common.logging import configure_logging  # noqa: E402
from forensics.ledger import verifier  # noqa: E402
from forensics.ledger.chain import verify_inclusion  # noqa: E402


def dsn_from_env() -> str:
    if url := os.environ.get("DATABASE_URL"):
        return url
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "forensics")
    user = os.environ.get("POSTGRES_USER", "forensics")
    password = os.environ.get("POSTGRES_PASSWORD", "")
    return f"host={host} port={port} dbname={db} user={user} password={password}"


def seal_all(connection, batch_size: int) -> int:
    """Seal every pending digest. Returns the number of blocks written."""
    blocks = 0
    while True:
        with connection.cursor() as cur:
            cur.execute("SELECT * FROM ledger.seal_block(%s)", (batch_size,))
            if not cur.fetchall():
                return blocks
        blocks += 1


def prove(connection, event_id: str) -> int:
    """Print and check an inclusion proof for one event."""
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT d.occurred_at, d.digest, b.sequence_number, b.merkle_root
              FROM ledger.event_digests d
              JOIN ledger.chain_blocks b USING (block_id)
             WHERE d.event_id = %s
            """,
            (event_id,),
        )
        row = cur.fetchone()
        if row is None:
            print(f"event {event_id} is not sealed into any block", file=sys.stderr)
            return 2
        occurred_at, digest, sequence, root = row

        cur.execute(
            "SELECT sibling, sibling_is_left FROM ledger.inclusion_proof(%s, %s) "
            "ORDER BY tree_level",
            (event_id, occurred_at),
        )
        proof = [(bytes(s), bool(left)) for s, left in cur.fetchall()]

    ok = verify_inclusion(bytes(digest), proof, bytes(root))
    print(f"event        {event_id}")
    print(f"block        #{sequence}")
    print(f"leaf digest  {bytes(digest).hex()}")
    print(f"merkle root  {bytes(root).hex()}")
    print(f"proof        {len(proof)} sibling hashes")
    for depth, (sibling, is_left) in enumerate(proof):
        side = "left " if is_left else "right"
        print(f"  level {depth:>2}  {side}  {sibling.hex()}")
    print(f"\nverified: {'YES' if ok else 'NO'}")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seal", action="store_true", help="seal pending events first")
    parser.add_argument("--batch-size", type=int, default=10_000)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--prove", metavar="EVENT_ID", help="print an inclusion proof")
    parser.add_argument("--quiet", action="store_true", help="only print findings")
    args = parser.parse_args()

    configure_logging(
        service="ledger-verifier",
        environment=os.environ.get("APP_ENV", "local"),
        level="WARNING" if (args.quiet or args.json) else "INFO",
        stream=sys.stderr,
    )

    try:
        connection = psycopg.connect(dsn_from_env(), autocommit=True)
    except psycopg.Error as exc:
        print(f"cannot connect: {exc}", file=sys.stderr)
        return 2

    with connection:
        if args.prove:
            return prove(connection, args.prove)

        if args.seal:
            blocks = seal_all(connection, args.batch_size)
            if not args.json:
                print(f"sealed {blocks} new block(s)")

        report = verifier.verify(connection)

    if args.json:
        print(json.dumps(
            {
                "intact": report.intact,
                "events_checked": report.events_checked,
                "blocks_checked": report.blocks_checked,
                "unsealed_events": report.unsealed_events,
                "findings": [dataclasses.asdict(f) for f in report.findings],
            },
            indent=2,
        ))
        return 0 if report.intact else 1

    print(report.summary())
    if report.unsealed_events:
        # Not a finding, but the window in which a coordinated edit to both a row
        # and its digest would go unnoticed. Worth surfacing every time.
        print(
            f"note: {report.unsealed_events} event(s) are digested but unsealed; "
            "run with --seal to close the window"
        )
    for finding in report.findings:
        print(f"  {finding}")

    return 0 if report.intact else 1


if __name__ == "__main__":
    raise SystemExit(main())
