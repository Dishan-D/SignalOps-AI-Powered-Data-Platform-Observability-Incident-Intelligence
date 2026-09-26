"""The evidence ledger against a real PostgreSQL.

Two things are proved here that cannot be proved in isolation:

1. The SQL and Python implementations of the hashing protocol agree byte for
   byte. They are deliberate duplicates — a ledger verified only by the database
   that stores it proves little — so a divergence in either must fail the build.
2. Tampering is actually detected, at every layer, including the case where the
   attacker updates an event *and* its digest together.
"""

from __future__ import annotations

import psycopg
import pytest

from forensics.ledger import verifier
from forensics.ledger.chain import (
    EVENT_FIELDS,
    block_hash,
    canonical_event,
    event_digest,
    genesis_hash,
    merkle_root,
    verify_inclusion,
)
from tests.db.helpers import generate, land, normalize


@pytest.fixture
def sealed(conn):
    """A populated, fully sealed ledger."""
    land(conn, generate(1200, host_count=6, user_count=15, anomaly_rate=0.05, seed=777))
    normalize(conn)
    blocks = 0
    while True:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM ledger.seal_block(400)")
            if not cur.fetchall():
                break
        blocks += 1
    assert blocks >= 2, "expected several blocks so the chain has real links"
    return conn


def _scalar(conn, sql: str, *params):
    with conn.cursor() as cur:
        cur.execute(sql, params or None)
        row = cur.fetchone()
        return row[0] if row else None


def _findings(conn, sql: str) -> list[tuple]:
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchall()


# --------------------------------------------------------------------------- #
# Digest-on-insert                                                             #
# --------------------------------------------------------------------------- #

def test_every_inserted_event_is_digested(conn) -> None:
    """No committed evidence may exist unhashed."""
    land(conn, generate(500, host_count=4, anomaly_rate=0.05, seed=1))
    normalize(conn)

    assert _scalar(conn, "SELECT count(*) FROM evidence.events") == 500
    assert _scalar(conn, "SELECT count(*) FROM ledger.event_digests") == 500
    assert _scalar(conn, """
        SELECT count(*) FROM evidence.events e
        LEFT JOIN ledger.event_digests d
          ON d.event_id = e.event_id AND d.occurred_at = e.occurred_at
        WHERE d.event_id IS NULL
    """) == 0


def test_idempotent_replay_does_not_disturb_an_existing_digest(conn) -> None:
    """Re-normalising the same events must not rewrite a digest already sealed."""
    land(conn, generate(300, host_count=3, anomaly_rate=0.05, seed=2))
    normalize(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM ledger.seal_block(1000)")
        cur.fetchall()
    before = _scalar(conn, "SELECT md5(string_agg(encode(digest,'hex'), '' ORDER BY event_id)) "
                           "FROM ledger.event_digests")

    with conn.cursor() as cur:
        cur.execute("UPDATE evidence.raw_events SET normalized_at = NULL")
    normalize(conn)

    assert _scalar(conn, "SELECT md5(string_agg(encode(digest,'hex'), '' ORDER BY event_id)) "
                         "FROM ledger.event_digests") == before
    assert _scalar(conn, "SELECT count(*) FROM ledger.event_digests WHERE block_id IS NULL") == 0


# --------------------------------------------------------------------------- #
# SQL / Python agreement                                                       #
# --------------------------------------------------------------------------- #

def test_canonical_form_matches_between_sql_and_python(sealed) -> None:
    columns = ", ".join(f"e.{name}" for name in EVENT_FIELDS)
    with sealed.cursor() as cur:
        cur.execute(
            f"SELECT {columns}, ledger.canonical_event(e.*), ledger.event_digest(e.*) "
            f"FROM evidence.events e ORDER BY e.occurred_at, e.event_id LIMIT 500"
        )
        rows = cur.fetchall()

    assert rows
    width = len(EVENT_FIELDS)
    for row in rows:
        record = dict(zip(EVENT_FIELDS, row[:width], strict=True))
        assert canonical_event(record) == row[width]
        assert event_digest(record) == bytes(row[width + 1])


def test_genesis_matches_between_sql_and_python(sealed) -> None:
    assert bytes(_scalar(sealed, "SELECT ledger.genesis_hash()")) == genesis_hash()


def test_merkle_roots_and_block_hashes_match_python(sealed) -> None:
    with sealed.cursor() as cur:
        cur.execute(
            "SELECT block_id, sequence_number, prev_hash, merkle_root, block_hash, event_count "
            "FROM ledger.chain_blocks ORDER BY sequence_number"
        )
        blocks = cur.fetchall()

    assert blocks
    for block_id, sequence, prev, root, stored_hash, count in blocks:
        with sealed.cursor() as cur:
            cur.execute(
                "SELECT digest FROM ledger.event_digests WHERE block_id = %s "
                "ORDER BY digested_at, event_id",
                (block_id,),
            )
            leaves = [bytes(r[0]) for r in cur.fetchall()]
        assert merkle_root(leaves) == bytes(root)
        assert block_hash(bytes(prev), bytes(root), sequence, count) == bytes(stored_hash)


# --------------------------------------------------------------------------- #
# Chain structure                                                              #
# --------------------------------------------------------------------------- #

def test_intact_ledger_verifies_clean_both_ways(sealed) -> None:
    assert _findings(sealed, "SELECT * FROM ledger.verify_events()") == []
    assert _findings(sealed, "SELECT * FROM ledger.verify_chain()") == []
    assert verifier.verify(sealed).intact


def test_first_block_anchors_to_genesis(sealed) -> None:
    prev = _scalar(sealed, "SELECT prev_hash FROM ledger.chain_blocks WHERE sequence_number = 0")
    assert bytes(prev) == genesis_hash()


def test_each_block_links_to_its_predecessor(sealed) -> None:
    with sealed.cursor() as cur:
        cur.execute(
            "SELECT sequence_number, prev_hash, block_hash FROM ledger.chain_blocks "
            "ORDER BY sequence_number"
        )
        blocks = cur.fetchall()
    for (_, _, previous_hash), (_, prev_hash, _) in zip(blocks, blocks[1:], strict=False):
        assert bytes(prev_hash) == bytes(previous_hash)


def test_sealing_is_exhaustive_and_repeatable(sealed) -> None:
    assert _scalar(sealed, "SELECT ledger.unsealed_events()") == 0
    # Nothing left to seal: a further call is a no-op, not an empty block.
    assert _findings(sealed, "SELECT * FROM ledger.seal_block(1000)") == []


def test_block_event_counts_sum_to_the_digest_count(sealed) -> None:
    assert (
        _scalar(sealed, "SELECT sum(event_count) FROM ledger.chain_blocks")
        == _scalar(sealed, "SELECT count(*) FROM ledger.event_digests")
    )


# --------------------------------------------------------------------------- #
# Tamper detection                                                             #
# --------------------------------------------------------------------------- #

def test_modifying_an_event_is_detected(sealed) -> None:
    with sealed.cursor() as cur:
        cur.execute(
            "UPDATE evidence.events SET message = 'nothing to see here' "
            "WHERE event_id = (SELECT event_id FROM evidence.events LIMIT 1)"
        )

    kinds = {row[0] for row in _findings(sealed, "SELECT * FROM ledger.verify_events()")}
    assert "event_modified" in kinds

    report = verifier.verify(sealed)
    assert not report.intact
    assert any(f.kind == "event_modified" for f in report.findings)


def test_coordinated_edit_to_event_and_digest_is_still_detected(sealed) -> None:
    """The attack the per-event digest alone cannot stop.

    Rewriting the row *and* recomputing its digest satisfies layer 1. The block's
    Merkle root, which was sealed over the original digest, does not.
    """
    with sealed.cursor() as cur:
        cur.execute(
            "UPDATE evidence.events SET message = 'scrubbed' "
            "WHERE event_id = (SELECT event_id FROM evidence.events LIMIT 1)"
        )
        cur.execute(
            "UPDATE ledger.event_digests d SET digest = ledger.event_digest(e.*) "
            "FROM evidence.events e "
            "WHERE e.event_id = d.event_id AND e.occurred_at = d.occurred_at "
            "AND e.message = 'scrubbed'"
        )

    # Layer 1 now passes — row and digest agree.
    assert _findings(sealed, "SELECT * FROM ledger.verify_events()") == []

    # Layer 2 does not.
    kinds = {row[0] for row in _findings(sealed, "SELECT * FROM ledger.verify_chain()")}
    assert "merkle_root_mismatch" in kinds

    report = verifier.verify(sealed)
    assert not report.intact
    assert any(f.kind == "merkle_root_mismatch" for f in report.findings)


def test_deleting_an_event_is_detected(sealed) -> None:
    with sealed.cursor() as cur:
        cur.execute(
            "DELETE FROM evidence.events "
            "WHERE event_id = (SELECT event_id FROM evidence.events LIMIT 1)"
        )

    kinds = {row[0] for row in _findings(sealed, "SELECT * FROM ledger.verify_events()")}
    assert "event_deleted" in kinds
    assert any(f.kind == "event_deleted" for f in verifier.verify(sealed).findings)


def test_removing_a_block_breaks_the_chain(sealed) -> None:
    with sealed.cursor() as cur:
        cur.execute("DELETE FROM ledger.chain_blocks WHERE sequence_number = 1")

    kinds = {row[0] for row in _findings(sealed, "SELECT * FROM ledger.verify_chain()")}
    assert "sequence_gap" in kinds
    assert "broken_link" in kinds

    report = verifier.verify(sealed)
    assert {f.kind for f in report.findings} >= {"sequence_gap", "broken_link"}


def test_editing_a_block_hash_is_detected(sealed) -> None:
    with sealed.cursor() as cur:
        cur.execute(
            "UPDATE ledger.chain_blocks SET block_hash = digest('forged','sha256') "
            "WHERE sequence_number = 0"
        )

    kinds = {row[0] for row in _findings(sealed, "SELECT * FROM ledger.verify_chain()")}
    assert "block_hash_mismatch" in kinds


def test_editing_a_merkle_root_is_detected(sealed) -> None:
    with sealed.cursor() as cur:
        cur.execute(
            "UPDATE ledger.chain_blocks SET merkle_root = digest('forged','sha256') "
            "WHERE sequence_number = 0"
        )

    kinds = {row[0] for row in _findings(sealed, "SELECT * FROM ledger.verify_chain()")}
    # The root no longer covers the digests, and the block hash no longer covers
    # the root — both layers object.
    assert "merkle_root_mismatch" in kinds
    assert "block_hash_mismatch" in kinds


def test_deleting_a_digest_orphans_its_event(sealed) -> None:
    with sealed.cursor() as cur:
        cur.execute(
            "DELETE FROM ledger.event_digests "
            "WHERE event_id = (SELECT event_id FROM ledger.event_digests LIMIT 1)"
        )

    kinds = {row[0] for row in _findings(sealed, "SELECT * FROM ledger.verify_events()")}
    assert "event_undigested" in kinds
    chain_kinds = {row[0] for row in _findings(sealed, "SELECT * FROM ledger.verify_chain()")}
    assert "event_count_mismatch" in chain_kinds


# --------------------------------------------------------------------------- #
# Inclusion proofs                                                             #
# --------------------------------------------------------------------------- #

def test_inclusion_proof_verifies_against_the_block_root(sealed) -> None:
    with sealed.cursor() as cur:
        cur.execute(
            "SELECT d.event_id, d.occurred_at, d.digest, b.merkle_root "
            "FROM ledger.event_digests d JOIN ledger.chain_blocks b USING (block_id) "
            "LIMIT 5"
        )
        samples = cur.fetchall()

    assert samples
    for event_id, occurred_at, digest, root in samples:
        with sealed.cursor() as cur:
            cur.execute(
                "SELECT sibling, sibling_is_left FROM ledger.inclusion_proof(%s, %s) "
                "ORDER BY tree_level",
                (event_id, occurred_at),
            )
            proof = [(bytes(s), bool(left)) for s, left in cur.fetchall()]
        assert verify_inclusion(bytes(digest), proof, bytes(root)), event_id


def test_inclusion_proof_rejects_a_forged_digest(sealed) -> None:
    with sealed.cursor() as cur:
        cur.execute(
            "SELECT d.event_id, d.occurred_at, d.digest, b.merkle_root "
            "FROM ledger.event_digests d JOIN ledger.chain_blocks b USING (block_id) LIMIT 1"
        )
        event_id, occurred_at, digest, root = cur.fetchone()
        cur.execute(
            "SELECT sibling, sibling_is_left FROM ledger.inclusion_proof(%s, %s) "
            "ORDER BY tree_level",
            (event_id, occurred_at),
        )
        proof = [(bytes(s), bool(left)) for s, left in cur.fetchall()]

    forged = bytes(digest)[:-1] + bytes([bytes(digest)[-1] ^ 0xFF])
    assert not verify_inclusion(forged, proof, bytes(root))


def test_unsealed_event_has_no_proof(conn) -> None:
    land(conn, generate(100, host_count=2, anomaly_rate=0.0, seed=9))
    normalize(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT event_id, occurred_at FROM ledger.event_digests LIMIT 1")
        event_id, occurred_at = cur.fetchone()
        cur.execute(
            "SELECT count(*) FROM ledger.inclusion_proof(%s, %s)", (event_id, occurred_at)
        )
        assert cur.fetchone()[0] == 0


# --------------------------------------------------------------------------- #
# Append-only enforcement                                                      #
# --------------------------------------------------------------------------- #

def test_application_role_cannot_rewrite_the_ledger(sealed, migrated_db) -> None:
    """A chain its writer can rewrite is not tamper-evident.

    The grants are the enforcement; this asserts they are actually in place, not
    merely intended.
    """
    with sealed.cursor() as cur:
        cur.execute("""
            SELECT privilege_type FROM information_schema.role_table_grants
            WHERE grantee = 'forensics_app' AND table_schema = 'ledger'
        """)
        granted = {row[0] for row in cur.fetchall()}

    assert "SELECT" in granted
    assert "UPDATE" not in granted, "the ledger must not be updatable by the app role"
    assert "DELETE" not in granted, "the ledger must not be deletable by the app role"


def test_digest_column_length_is_constrained(sealed) -> None:
    """A truncated or padded digest is a corrupted one."""
    with sealed.cursor() as cur, pytest.raises(psycopg.errors.CheckViolation):
        cur.execute(
            "INSERT INTO ledger.event_digests (event_id, occurred_at, digest) "
            "VALUES (gen_random_uuid(), now(), '\\x00'::bytea)"
        )
