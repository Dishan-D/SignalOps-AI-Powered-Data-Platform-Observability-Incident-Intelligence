"""The SQL transform: correctness, idempotency, and the bugs that bit before."""

from __future__ import annotations

import pytest

from tests.db.helpers import generate, land, normalize


def _count(conn, sql: str) -> int:
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchone()[0]


def test_every_landed_row_is_normalized(conn) -> None:
    events = generate(2000, host_count=10, user_count=20, anomaly_rate=0.05, seed=1)
    land(conn, events)
    normalized, failed = normalize(conn)

    assert failed == 0
    assert normalized == 2000
    assert _count(conn, "SELECT count(*) FROM evidence.events") == 2000


def test_dimensions_are_deduplicated(conn) -> None:
    """The point of the dimension tables: entities stored once, not per event."""
    events = generate(3000, host_count=8, user_count=15, anomaly_rate=0.0, seed=2)
    land(conn, events)
    normalize(conn)

    # 8 hosts, whatever the event volume.
    assert _count(conn, "SELECT count(*) FROM evidence.hosts") == 8
    # 15 humans + the 4 service accounts the generator always creates.
    assert _count(conn, "SELECT count(*) FROM evidence.users") == 19
    # Addresses must compress substantially — this is what caught the original
    # (ip, port) keying, which produced ~1 dimension row per fact.
    addresses = _count(conn, "SELECT count(*) FROM evidence.network_addresses")
    assert addresses < 3000 / 2, f"address dimension not compressing: {addresses}"


def test_replay_is_idempotent(conn) -> None:
    """At-least-once delivery must not duplicate evidence."""
    events = generate(1000, host_count=5, anomaly_rate=0.1, seed=3)
    land(conn, events)
    normalize(conn)
    before = _count(conn, "SELECT count(*) FROM evidence.events")

    # Simulate redelivery of the identical batch.
    with conn.cursor() as cur:
        cur.execute("UPDATE evidence.raw_events SET normalized_at = NULL")
    normalize(conn)

    assert _count(conn, "SELECT count(*) FROM evidence.events") == before
    assert _count(conn, "SELECT count(*) FROM analytics.event_labels") > 0


def test_no_orphaned_foreign_keys(conn) -> None:
    events = generate(1500, host_count=6, anomaly_rate=0.1, seed=4)
    land(conn, events)
    normalize(conn)

    assert _count(conn, """
        SELECT count(*) FROM evidence.events e
        LEFT JOIN evidence.hosts h USING (host_id) WHERE h.host_id IS NULL
    """) == 0
    assert _count(conn, """
        SELECT count(*) FROM evidence.events e
        LEFT JOIN evidence.users u USING (user_id)
        WHERE e.user_id IS NOT NULL AND u.user_id IS NULL
    """) == 0


def test_identity_sequences_are_not_burned_by_upserts(conn) -> None:
    """Regression: ON CONFLICT DO UPDATE calls nextval() even when it conflicts.

    Upserting a handful of dataset names once per event exhausted a SMALLINT
    identity sequence at 32 767 and failed 29 233 of 50 000 rows. The transform
    now guards dimension inserts with NOT EXISTS, so the sequence advances only
    for genuinely new values.
    """
    events = generate(4000, host_count=4, anomaly_rate=0.0, seed=5)
    land(conn, events)
    normalize(conn)

    dataset_count = _count(conn, "SELECT count(*) FROM evidence.datasets")
    with conn.cursor() as cur:
        cur.execute("SELECT last_value FROM evidence.datasets_dataset_id_seq")
        last_value = cur.fetchone()[0]

    # Allowance for the ON CONFLICT guard, not one nextval per event.
    assert last_value <= dataset_count + 5, (
        f"sequence burned to {last_value} for only {dataset_count} datasets"
    )


def test_ground_truth_lands_in_analytics_not_evidence(conn) -> None:
    """Labels must be structurally separate from observed evidence."""
    events = generate(2000, host_count=5, anomaly_rate=0.2, seed=6)
    land(conn, events)
    normalize(conn)

    assert _count(conn, "SELECT count(*) FROM analytics.event_labels") > 0

    # No column of the evidence fact table may carry a label.
    with conn.cursor() as cur:
        cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = 'evidence' AND table_name = 'events'
        """)
        columns = {r[0] for r in cur.fetchall()}
    assert not any("anomaly" in c or "eval" in c or "scenario" in c for c in columns)


def test_labels_join_back_to_events(conn) -> None:
    events = generate(2000, host_count=5, anomaly_rate=0.2, seed=7)
    land(conn, events)
    normalize(conn)

    assert _count(conn, """
        SELECT count(*) FROM analytics.event_labels l
        JOIN evidence.events e USING (event_id, occurred_at)
    """) == _count(conn, "SELECT count(*) FROM analytics.event_labels")


def test_partitions_are_created_and_used(conn) -> None:
    events = generate(500, host_count=3, anomaly_rate=0.0, seed=8)
    land(conn, events)
    normalize(conn)

    # Nothing should fall through to DEFAULT: a row there is not partition-pruned.
    assert _count(conn, "SELECT count(*) FROM evidence.events_default") == 0
    assert _count(conn, """
        SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'evidence' AND c.relname ~ '^events_[0-9]{4}_[0-9]{2}$'
    """) >= 1


def test_malformed_address_does_not_fail_the_event(conn) -> None:
    """safe_inet must degrade to NULL rather than reject a valid event."""
    events = generate(10, host_count=2, anomaly_rate=0.0, seed=9)
    land(conn, events)
    with conn.cursor() as cur:
        cur.execute("UPDATE evidence.raw_events SET host_ip = 'not-an-ip'")
    normalized, failed = normalize(conn)

    assert failed == 0
    assert normalized == 10
    assert _count(conn, "SELECT count(*) FROM evidence.hosts WHERE ip IS NULL") > 0


def test_missing_event_time_is_recorded_as_an_error(conn) -> None:
    events = generate(20, host_count=2, anomaly_rate=0.0, seed=10)
    land(conn, events)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE evidence.raw_events SET event_time = NULL "
            "WHERE raw_id IN (SELECT raw_id FROM evidence.raw_events LIMIT 5)"
        )
    normalized, failed = normalize(conn)

    assert normalized == 15
    assert failed == 5
    assert _count(conn, """
        SELECT count(*) FROM evidence.raw_events
        WHERE normalize_error = 'missing_event_time'
    """) == 5


@pytest.mark.parametrize("batch_size", [100, 500])
def test_batching_drains_the_backlog_completely(conn, batch_size: int) -> None:
    events = generate(1000, host_count=4, anomaly_rate=0.05, seed=11)
    land(conn, events)

    total = 0
    for _ in range(50):
        normalized, _ = normalize(conn, batch_size=batch_size)
        total += normalized
        if _count(conn, "SELECT count(*) FROM evidence.raw_events "
                        "WHERE normalized_at IS NULL") == 0:
            break

    assert total == 1000
    assert _count(conn, "SELECT count(*) FROM evidence.events") == 1000
