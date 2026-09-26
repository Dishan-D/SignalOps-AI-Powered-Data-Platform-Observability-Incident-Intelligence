"""Fixtures for tests that need a real PostgreSQL.

Skipped unless a database is reachable, so `make test` stays runnable with no
infrastructure. Point them at the Compose stack (or any Postgres) with:

    POSTGRES_HOST=localhost POSTGRES_PORT=5432 POSTGRES_PASSWORD=... make test-db
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

psycopg = pytest.importorskip("psycopg", reason="psycopg not installed")

REPO_ROOT = Path(__file__).resolve().parents[2]


def _dsn() -> str:
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "forensics")
    user = os.environ.get("POSTGRES_USER", "forensics")
    password = os.environ.get("POSTGRES_PASSWORD", "")
    return f"host={host} port={port} dbname={db} user={user} password={password}"


@pytest.fixture(scope="session")
def migrated_db() -> str:
    """A database with db/init and every migration applied."""
    dsn = _dsn()
    try:
        with psycopg.connect(dsn, connect_timeout=5):
            pass
    except psycopg.Error as exc:
        pytest.skip(f"no PostgreSQL reachable ({exc.__class__.__name__}); set POSTGRES_*")

    # Bootstrap is idempotent, so applying it here is safe on a warm database.
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute((REPO_ROOT / "db" / "init" / "00_bootstrap.sql").read_text()
                    .replace("\\set ON_ERROR_STOP on", ""))

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "migrate.py")],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert result.returncode == 0, f"migrations failed:\n{result.stdout}\n{result.stderr}"
    return dsn


@pytest.fixture
def conn(migrated_db: str):
    """Connection with the evidence tables truncated for a clean slate."""
    with psycopg.connect(migrated_db, autocommit=True) as connection:
        with connection.cursor() as cur:
            # RESTART IDENTITY matters: plain TRUNCATE leaves sequences where
            # they were, so a per-test assertion about sequence consumption
            # would actually measure the whole session.
            cur.execute(
                "TRUNCATE evidence.raw_events, evidence.events, "
                "analytics.event_labels RESTART IDENTITY"
            )
            cur.execute(
                "TRUNCATE evidence.hosts, evidence.users, evidence.process_images, "
                "evidence.network_addresses, evidence.datasets "
                "RESTART IDENTITY CASCADE"
            )
            # The ledger must be cleared too. Digests outlive a truncated
            # evidence table and would surface in the next test as orphans —
            # which is exactly what the tamper tests look for.
            cur.execute(
                "TRUNCATE ledger.event_digests, ledger.chain_blocks RESTART IDENTITY"
            )
        yield connection
