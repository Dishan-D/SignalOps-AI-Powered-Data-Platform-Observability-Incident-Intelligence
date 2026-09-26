#!/usr/bin/env python3
"""Load generated telemetry straight into the evidence store.

Bypasses Kafka and Spark so the database, the 3NF transform and the ledger can
be exercised without the streaming tier — useful for a demo, for a laptop with
no Docker, and for benchmarking the SQL path in isolation.

    python scripts/seed_evidence.py                     # 20k events, seal, verify
    python scripts/seed_evidence.py --events 100000     # bigger
    python scripts/seed_evidence.py --truncate          # start from empty
    python scripts/seed_evidence.py --no-seal           # leave events unsealed

Connection comes from the usual POSTGRES_* variables (or DATABASE_URL).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

try:
    import psycopg
except ImportError:  # pragma: no cover - dependency guidance
    print("psycopg is required: pip install 'psycopg[binary]'", file=sys.stderr)
    raise SystemExit(2) from None

from forensics.ingestion.generators import TelemetryGenerator  # noqa: E402
from forensics.ingestion.landing import copy_statement, to_raw_row  # noqa: E402


def dsn_from_env() -> str:
    if url := os.environ.get("DATABASE_URL"):
        return url
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    database = os.environ.get("POSTGRES_DB", "forensics")
    user = os.environ.get("POSTGRES_USER", "forensics")
    password = os.environ.get("POSTGRES_PASSWORD", "")
    return f"host={host} port={port} dbname={database} user={user} password={password}"


def truncate(connection) -> None:
    """Reset every table the seeder touches, identities included."""
    with connection.cursor() as cur:
        cur.execute(
            "TRUNCATE evidence.raw_events, evidence.events, analytics.event_labels "
            "RESTART IDENTITY"
        )
        cur.execute(
            "TRUNCATE evidence.hosts, evidence.users, evidence.process_images, "
            "evidence.network_addresses, evidence.datasets RESTART IDENTITY CASCADE"
        )
        cur.execute("TRUNCATE ledger.event_digests, ledger.chain_blocks RESTART IDENTITY")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=20_000)
    parser.add_argument("--hosts", type=int, default=25)
    parser.add_argument("--users", type=int, default=60)
    parser.add_argument("--anomaly-rate", type=float, default=0.03)
    parser.add_argument("--seed", type=int, default=None, help="reproducible stream")
    parser.add_argument("--batch-size", type=int, default=10_000, help="normalise batch")
    parser.add_argument("--truncate", action="store_true", help="clear existing evidence first")
    parser.add_argument("--no-seal", action="store_true", help="leave events unsealed")
    args = parser.parse_args()

    try:
        connection = psycopg.connect(dsn_from_env(), autocommit=True)
    except psycopg.Error as exc:
        print(f"cannot connect: {exc}", file=sys.stderr)
        print("hint: set POSTGRES_HOST/PORT/DB/USER/PASSWORD, and run migrations first",
              file=sys.stderr)
        return 2

    with connection:
        # Fail early with a clear message rather than a confusing SQL error.
        with connection.cursor() as cur:
            cur.execute(
                "SELECT to_regclass('evidence.raw_events'), to_regclass('ledger.chain_blocks')"
            )
            raw_table, ledger_table = cur.fetchone()
        if raw_table is None or ledger_table is None:
            print("schema is missing; run: python scripts/migrate.py", file=sys.stderr)
            return 2

        if args.truncate:
            truncate(connection)
            print("cleared existing evidence")

        generator = TelemetryGenerator(
            host_count=args.hosts,
            user_count=args.users,
            anomaly_rate=args.anomaly_rate,
            seed=args.seed,
        )
        events = []
        started = time.perf_counter()
        while len(events) < args.events:
            events.extend(generator.next_events())
        events = events[: args.events]
        print(f"generated   {len(events):>8,} events  ({time.perf_counter() - started:.1f}s)")

        # Offsets continue from whatever is already loaded so repeated seeding
        # does not produce colliding Kafka coordinates.
        with connection.cursor() as cur:
            cur.execute("SELECT coalesce(max(kafka_offset), -1) + 1 FROM evidence.raw_events")
            start_offset = int(cur.fetchone()[0])

        started = time.perf_counter()
        with connection.cursor() as cur, cur.copy(copy_statement()) as copy:
            for index, event in enumerate(events, start=start_offset):
                copy.write_row(to_raw_row(event, index))
        print(f"landed      {len(events):>8,} rows    ({time.perf_counter() - started:.1f}s)")

        started = time.perf_counter()
        normalized = failed = 0
        while True:
            with connection.cursor() as cur:
                cur.execute("SELECT * FROM evidence.normalize_raw_events(%s)", (args.batch_size,))
                done, bad = cur.fetchone()
            normalized += int(done)
            failed += int(bad)
            if done == 0 and bad == 0:
                break
        elapsed = max(time.perf_counter() - started, 1e-9)
        print(f"normalised  {normalized:>8,} rows    ({elapsed:.1f}s, "
              f"{normalized / elapsed:,.0f} rows/s){f', {failed} failed' if failed else ''}")

        if not args.no_seal:
            started = time.perf_counter()
            blocks = 0
            while True:
                with connection.cursor() as cur:
                    cur.execute("SELECT * FROM ledger.seal_block(%s)", (args.batch_size,))
                    if not cur.fetchall():
                        break
                blocks += 1
            print(f"sealed      {blocks:>8,} blocks   ({time.perf_counter() - started:.1f}s)")

        with connection.cursor() as cur:
            cur.execute("""
                SELECT (SELECT count(*) FROM evidence.events),
                       (SELECT count(*) FROM evidence.hosts),
                       (SELECT count(*) FROM evidence.network_addresses),
                       (SELECT count(*) FROM analytics.event_labels),
                       (SELECT count(*) FROM ledger.chain_blocks),
                       (SELECT count(*) FROM ledger.event_digests WHERE block_id IS NULL)
            """)
            events_n, hosts, addresses, labels, blocks_n, unsealed = cur.fetchone()

    print(
        f"\nevidence.events      {events_n:>8,}"
        f"\nevidence.hosts       {hosts:>8,}"
        f"\nnetwork_addresses    {addresses:>8,}"
        f"\nground-truth labels  {labels:>8,}"
        f"\nledger blocks        {blocks_n:>8,}"
        f"\nunsealed events      {unsealed:>8,}"
    )
    print("\nnext: python scripts/verify_ledger.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
