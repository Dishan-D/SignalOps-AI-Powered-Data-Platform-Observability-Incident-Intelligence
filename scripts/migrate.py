#!/usr/bin/env python3
"""Forward-only SQL migration runner.

Deliberately small. A migration tool for this project needs to do four things,
and doing them in ~150 readable lines beats adding Alembic to a project whose
schema is hand-written DDL:

1. Apply ``db/migrations/NNNN_name.sql`` in lexical order, exactly once each.
2. Record every application in ``public.schema_migrations``.
3. Refuse to run if an already-applied file has been edited since — a changed
   checksum means the database and the repository disagree about history, and
   silently ignoring that is how environments drift apart.
4. Wrap each migration in a transaction, so a failure leaves nothing half-applied.

Usage:
    python scripts/migrate.py            # apply pending migrations
    python scripts/migrate.py --status   # show what is applied vs pending
    python scripts/migrate.py --dry-run  # list what would run
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import psycopg
except ImportError:  # pragma: no cover - dependency guidance
    print(
        "psycopg is required: pip install 'psycopg[binary]'",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "db" / "migrations"


@dataclass(frozen=True)
class Migration:
    version: str
    path: Path
    checksum: str

    @classmethod
    def from_path(cls, path: Path) -> Migration:
        content = path.read_bytes()
        return cls(
            version=path.stem,
            path=path,
            checksum=hashlib.sha256(content).hexdigest(),
        )


def discover() -> list[Migration]:
    """All migrations, ordered by filename (hence by the numeric prefix)."""
    return [Migration.from_path(p) for p in sorted(MIGRATIONS_DIR.glob("*.sql"))]


def dsn_from_env() -> str:
    """Build a connection string from the same variables Compose sets."""
    if url := os.environ.get("DATABASE_URL"):
        return url
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "forensics")
    user = os.environ.get("POSTGRES_USER", "forensics")
    password = os.environ.get("POSTGRES_PASSWORD", "")
    return f"host={host} port={port} dbname={db} user={user} password={password}"


def applied_migrations(conn: psycopg.Connection) -> dict[str, str]:
    """Map of version -> checksum already recorded in the database."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'schema_migrations'
            )
            """
        )
        row = cur.fetchone()
        if not row or not row[0]:
            # A database that has not run db/init yet. Create the ledger so the
            # runner works against a plain empty database too.
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS public.schema_migrations (
                    version     TEXT PRIMARY KEY,
                    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
                    checksum    TEXT NOT NULL,
                    description TEXT
                )
                """
            )
            conn.commit()
            return {}

        cur.execute("SELECT version, checksum FROM public.schema_migrations")
        return dict(cur.fetchall())


def verify_unchanged(migrations: list[Migration], applied: dict[str, str]) -> list[str]:
    """Return versions whose file no longer matches what was applied."""
    drifted = []
    for migration in migrations:
        recorded = applied.get(migration.version)
        # 'n/a' is the bootstrap row written by db/init, which has no file.
        if recorded and recorded not in ("n/a", migration.checksum):
            drifted.append(migration.version)
    return drifted


def apply(conn: psycopg.Connection, migration: Migration) -> None:
    """Run one migration and record it, atomically."""
    sql = migration.path.read_text()
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(sql)
        cur.execute(
            """
                INSERT INTO public.schema_migrations (version, checksum, description)
                VALUES (%s, %s, %s)
                ON CONFLICT (version) DO UPDATE
                    SET checksum = EXCLUDED.checksum, applied_at = now()
                """,
            (migration.version, migration.checksum, migration.path.name),
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", action="store_true", help="show state and exit")
    parser.add_argument("--dry-run", action="store_true", help="list pending, apply nothing")
    args = parser.parse_args()

    migrations = discover()
    if not migrations:
        print(f"no migrations found in {MIGRATIONS_DIR}")
        return 0

    with psycopg.connect(dsn_from_env(), autocommit=True) as conn:
        applied = applied_migrations(conn)

        drifted = verify_unchanged(migrations, applied)
        if drifted:
            print(
                "refusing to run: these applied migrations have been edited since "
                f"they were applied: {', '.join(drifted)}\n"
                "Migrations are immutable once applied — add a new one instead.",
                file=sys.stderr,
            )
            return 1

        pending = [m for m in migrations if m.version not in applied]

        if args.status:
            for m in migrations:
                mark = "applied" if m.version in applied else "pending"
                print(f"  [{mark}] {m.version}")
            return 0

        if not pending:
            print("database is up to date; nothing to apply")
            return 0

        if args.dry_run:
            for m in pending:
                print(f"  would apply {m.version}")
            return 0

        for m in pending:
            print(f"applying {m.version} ...", end=" ", flush=True)
            try:
                apply(conn, m)
            except psycopg.Error as exc:
                print("FAILED")
                print(f"  {exc}", file=sys.stderr)
                return 1
            print("ok")

    print(f"applied {len(pending)} migration(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
