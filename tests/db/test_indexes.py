"""The indexing strategy, checked against the planner rather than asserted.

An index that exists but is never chosen is dead weight, so these tests read
EXPLAIN output for the queries an investigation actually runs.
"""

from __future__ import annotations

import pytest

from tests.db.helpers import generate, land, normalize


@pytest.fixture(scope="module")
def loaded(migrated_db):
    """A module-scoped dataset big enough for the planner to prefer indexes."""
    import psycopg

    with psycopg.connect(migrated_db, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE evidence.raw_events, evidence.events, "
                        "analytics.event_labels")
            cur.execute("TRUNCATE evidence.hosts, evidence.users, "
                        "evidence.process_images, evidence.network_addresses, "
                        "evidence.datasets CASCADE")
        land(conn, generate(20_000, host_count=25, user_count=60,
                            anomaly_rate=0.05, seed=42))
        normalize(conn)
        with conn.cursor() as cur:
            cur.execute("ANALYZE")
        yield conn


def _plan(conn, sql: str) -> str:
    """EXPLAIN a literal query.

    No parameters are passed: psycopg only treats '%' as a placeholder when a
    params argument is present, and these queries contain LIKE patterns.
    """
    with conn.cursor() as cur:
        cur.execute(f"EXPLAIN (ANALYZE, COSTS OFF) {sql}")
        return "\n".join(row[0] for row in cur.fetchall())


def test_host_timeline_uses_the_composite_index(loaded) -> None:
    plan = _plan(loaded, """
        SELECT event_id, occurred_at, message FROM evidence.events
        WHERE host_id = (SELECT host_id FROM evidence.hosts LIMIT 1)
        ORDER BY occurred_at DESC LIMIT 50
    """)
    assert "host_id_occurred_at" in plan
    assert "Seq Scan on events_2" not in plan


def test_partial_index_can_serve_a_failure_lookup(loaded) -> None:
    """The partial index must be *available* for the failure predicate.

    Asserted with seqscan disabled, for the same reason as the trigram test: at
    a few tens of thousands of rows a sequential scan is often genuinely cheaper
    and it is correct for the planner to choose it. Which way it goes also moves
    with the share of rows that are failures — so asserting a planner preference
    here would make the test a hostage to the data generator's mix.
    """
    with loaded.cursor() as cur:
        cur.execute("SET enable_seqscan = off")
        try:
            cur.execute(
                "EXPLAIN (COSTS OFF) SELECT count(*) FROM evidence.events "
                "WHERE outcome = 'failure' AND occurred_at > now() - interval '30 days'"
            )
            plan = "\n".join(r[0] for r in cur.fetchall())
        finally:
            cur.execute("RESET enable_seqscan")

    assert "Index" in plan, plan
    assert "Seq Scan on events_2" not in plan, plan


def test_partial_failure_index_exists_and_is_partial(loaded) -> None:
    """A partial index that silently became a full one costs what it was meant
    to save."""
    with loaded.cursor() as cur:
        cur.execute("""
            SELECT indexdef FROM pg_indexes
            WHERE schemaname = 'evidence' AND indexname = 'events_failures_idx'
        """)
        row = cur.fetchone()
    assert row is not None, "events_failures_idx is missing"
    assert "WHERE" in row[0].upper() and "failure" in row[0]


def test_trigram_index_can_serve_a_leading_wildcard_like(loaded) -> None:
    """A leading-wildcard LIKE is exactly what a B-tree cannot serve.

    Asserted with seqscan disabled rather than by hoping the planner picks the
    index: on a 20k-row table a sequential scan is genuinely cheaper, and it is
    correct for the planner to choose it. What matters is that a GIN trigram
    scan is *available* for this predicate — a B-tree would leave the planner no
    option but a full scan however large the table grew.
    """
    with loaded.cursor() as cur:
        # Session-level SET, not SET LOCAL: the connection is in autocommit, so
        # SET LOCAL would be scoped to a transaction that ends immediately.
        cur.execute("SET enable_seqscan = off")
        try:
            cur.execute(
                "EXPLAIN (COSTS OFF) SELECT count(*) FROM evidence.events "
                "WHERE message LIKE '%/dev/tcp/%'"
            )
            plan = "\n".join(r[0] for r in cur.fetchall())
        finally:
            cur.execute("RESET enable_seqscan")

    assert "Bitmap Index Scan" in plan, plan
    assert "message" in plan, plan


def test_trigram_search_returns_the_right_rows(loaded) -> None:
    """The index must not change results — reverse-shell commands are findable."""
    with loaded.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.events WHERE message LIKE '%/dev/tcp/%'"
        )
        assert cur.fetchone()[0] > 0


def test_destination_pivot_uses_its_index(loaded) -> None:
    plan = _plan(loaded, """
        SELECT count(*) FROM evidence.events
        WHERE destination_address_id =
              (SELECT address_id FROM evidence.network_addresses LIMIT 1)
    """)
    assert "destination_address_id" in plan


def test_every_declared_index_exists_on_the_partitions(loaded) -> None:
    """Parent-level indexes must propagate, or partitions scan sequentially."""
    with loaded.cursor() as cur:
        cur.execute("""
            SELECT count(*) FROM pg_indexes
            WHERE schemaname = 'evidence' AND tablename ~ '^events_[0-9]{4}_[0-9]{2}$'
        """)
        assert cur.fetchone()[0] >= 6


def test_brin_index_exists_on_each_partition(loaded) -> None:
    """BRIN is created per-partition by ensure_month_partition().

    Note it will not necessarily be *chosen* at test scale — a B-tree index-only
    scan wins on a small table. BRIN earns its place when the table is large
    enough that the B-tree no longer fits comfortably in cache.
    """
    with loaded.cursor() as cur:
        cur.execute("""
            SELECT count(*) FROM pg_indexes
            WHERE schemaname = 'evidence' AND indexdef LIKE '%USING brin%'
        """)
        assert cur.fetchone()[0] >= 1
