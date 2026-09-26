"""Hashing protocol: encoding, Merkle construction, inclusion proofs.

Pure Python — no database. The database-backed half (that SQL and Python agree,
and that tampering is actually detected) lives in tests/db/test_ledger.py.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import uuid

import pytest

from forensics.ledger.chain import (
    BLOCK_PREFIX,
    LEAF_PREFIX,
    NODE_PREFIX,
    Finding,
    VerificationReport,
    block_hash,
    canonical_event,
    encode_field,
    encode_timestamp,
    event_digest,
    genesis_hash,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_inclusion,
)

# --------------------------------------------------------------------------- #
# Field encoding                                                               #
# --------------------------------------------------------------------------- #

def test_encoding_is_length_prefixed() -> None:
    assert encode_field("abc") == "3:abc"


def test_byte_length_not_character_length() -> None:
    """A multibyte character must not shift the framing."""
    assert encode_field("é") == "2:é"
    assert encode_field("日本") == "6:日本"


def test_null_is_distinguishable_from_empty_string() -> None:
    assert encode_field(None) == "-1:"
    assert encode_field("") == "0:"
    assert encode_field(None) != encode_field("")


def test_delimiter_in_a_field_cannot_forge_a_boundary() -> None:
    """`message` is attacker-influenced text.

    With a plain separator, a crafted log line containing the delimiter could
    shift field boundaries so that two different records share a canonical form.
    The length prefix makes that impossible.
    """
    a = {"event_id": "x|y", "message": "z"}
    b = {"event_id": "x", "message": "y|z"}
    assert canonical_event(a) != canonical_event(b)


def test_crafted_length_prefix_in_content_does_not_collide() -> None:
    a = {"message": "5:hello"}
    b = {"message": "hello"}
    assert canonical_event(a) != canonical_event(b)


def test_timestamp_is_utc_with_microseconds() -> None:
    moment = dt.datetime(2026, 9, 9, 6, 53, 44, 532000, tzinfo=dt.UTC)
    assert encode_timestamp(moment) == "26:2026-09-09T06:53:44.532000"


def test_timestamp_offset_is_converted_not_relabelled() -> None:
    eastern = dt.timezone(dt.timedelta(hours=-5))
    aware = dt.datetime(2026, 9, 9, 1, 53, 44, 532000, tzinfo=eastern)
    utc = dt.datetime(2026, 9, 9, 6, 53, 44, 532000, tzinfo=dt.UTC)
    assert encode_timestamp(aware) == encode_timestamp(utc)


def test_naive_timestamp_is_treated_as_utc() -> None:
    naive = dt.datetime(2026, 9, 9, 6, 53, 44, 532000)
    assert "2026-09-09T06:53:44.532000" in encode_timestamp(naive)


def test_uuid_renders_like_postgres() -> None:
    value = uuid.UUID("65d78cbd-03f2-41a5-a03e-f1cb103776c6")
    assert encode_field(value) == "36:65d78cbd-03f2-41a5-a03e-f1cb103776c6"


def test_booleans_are_rejected_rather_than_silently_diverging() -> None:
    """Postgres renders booleans 't'/'f'; Python would render 'True'.

    No boolean is in the canonical field list today. If one is ever added, this
    fails loudly instead of producing digests the SQL side disagrees with.
    """
    with pytest.raises(TypeError, match="boolean"):
        encode_field(True)


def test_canonical_form_covers_every_declared_field() -> None:
    from forensics.ledger.chain import EVENT_FIELDS

    row = {name: f"v{index}" for index, name in enumerate(EVENT_FIELDS)}
    row["occurred_at"] = row["ingested_at"] = None
    canonical = canonical_event(row)
    assert canonical.count("|") == len(EVENT_FIELDS) - 1


def test_changing_any_field_changes_the_digest() -> None:
    from forensics.ledger.chain import EVENT_FIELDS

    base = dict.fromkeys(EVENT_FIELDS, "x")
    base["occurred_at"] = base["ingested_at"] = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    original = event_digest(base)

    for field in EVENT_FIELDS:
        mutated = dict(base)
        if field in ("occurred_at", "ingested_at"):
            mutated[field] = dt.datetime(2026, 1, 2, tzinfo=dt.UTC)
        else:
            mutated[field] = "y"
        assert event_digest(mutated) != original, f"{field} is not covered by the digest"


# --------------------------------------------------------------------------- #
# Domain separation                                                            #
# --------------------------------------------------------------------------- #

def test_leaf_and_node_hashes_are_domain_separated() -> None:
    """Without separation an internal node could be presented as a leaf — the
    classic Merkle second-preimage attack."""
    assert LEAF_PREFIX != NODE_PREFIX != BLOCK_PREFIX
    payload = b"\x00" * 32
    assert leaf_hash(payload.hex()) != node_hash(payload, payload)


def test_leaf_hash_matches_its_definition() -> None:
    assert leaf_hash("abc") == hashlib.sha256(LEAF_PREFIX + b"abc").digest()


def test_genesis_is_fixed_and_public() -> None:
    assert genesis_hash() == hashlib.sha256(b"forensics-ledger-genesis-v1").digest()
    assert len(genesis_hash()) == 32


# --------------------------------------------------------------------------- #
# Merkle tree                                                                  #
# --------------------------------------------------------------------------- #

def _leaves(count: int) -> list[bytes]:
    return [hashlib.sha256(str(i).encode()).digest() for i in range(count)]


def test_single_leaf_is_its_own_root() -> None:
    leaf = _leaves(1)
    assert merkle_root(leaf) == leaf[0]


def test_two_leaves_hash_as_a_pair() -> None:
    a, b = _leaves(2)
    assert merkle_root([a, b]) == node_hash(a, b)


def test_empty_tree_has_a_defined_root() -> None:
    assert len(merkle_root([])) == 32


def test_root_is_deterministic() -> None:
    leaves = _leaves(37)
    assert merkle_root(leaves) == merkle_root(list(leaves))


def test_reordering_leaves_changes_the_root() -> None:
    leaves = _leaves(8)
    shuffled = [leaves[1], leaves[0], *leaves[2:]]
    assert merkle_root(leaves) != merkle_root(shuffled)


def test_changing_one_leaf_changes_the_root() -> None:
    leaves = _leaves(16)
    mutated = list(leaves)
    mutated[7] = hashlib.sha256(b"tampered").digest()
    assert merkle_root(leaves) != merkle_root(mutated)


def test_odd_node_is_promoted_not_duplicated() -> None:
    """Regression for CVE-2012-2459.

    Bitcoin's construction duplicates a lone odd node, which lets [a, b, c] and
    [a, b, c, c] produce an identical root — a forged block that passes
    verification. Promoting the node unchanged avoids it.
    """
    a, b, c = _leaves(3)
    assert merkle_root([a, b, c]) != merkle_root([a, b, c, c])


@pytest.mark.parametrize("count", [1, 2, 3, 5, 8, 9, 17, 100, 1000])
def test_root_is_32_bytes_for_any_leaf_count(count: int) -> None:
    assert len(merkle_root(_leaves(count))) == 32


# --------------------------------------------------------------------------- #
# Inclusion proofs                                                             #
# --------------------------------------------------------------------------- #

def _build_proof(leaves: list[bytes], index: int) -> list[tuple[bytes, bool]]:
    """Reference proof builder, mirroring ledger.inclusion_proof."""
    proof: list[tuple[bytes, bool]] = []
    level = list(leaves)
    position = index
    while len(level) > 1:
        if position % 2 == 0:
            if position + 1 < len(level):
                proof.append((level[position + 1], False))
        else:
            proof.append((level[position - 1], True))

        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            nxt.append(node_hash(level[i], level[i + 1]) if i + 1 < len(level) else level[i])
        position //= 2
        level = nxt
    return proof


@pytest.mark.parametrize("count", [1, 2, 3, 4, 7, 8, 16, 33])
def test_every_leaf_can_prove_its_own_inclusion(count: int) -> None:
    leaves = _leaves(count)
    root = merkle_root(leaves)
    for index, leaf in enumerate(leaves):
        proof = _build_proof(leaves, index)
        assert verify_inclusion(leaf, proof, root), f"leaf {index} of {count}"


def test_proof_is_logarithmic_in_block_size() -> None:
    """The reason for a tree rather than a flat block hash: proving one event
    discloses O(log n) hashes, not the other n-1 events."""
    leaves = _leaves(1024)
    assert len(_build_proof(leaves, 500)) <= 12


def test_proof_rejects_a_tampered_leaf() -> None:
    leaves = _leaves(16)
    root = merkle_root(leaves)
    proof = _build_proof(leaves, 5)
    assert not verify_inclusion(hashlib.sha256(b"forged").digest(), proof, root)


def test_proof_rejects_a_tampered_sibling() -> None:
    leaves = _leaves(16)
    root = merkle_root(leaves)
    proof = _build_proof(leaves, 5)
    proof[0] = (hashlib.sha256(b"forged").digest(), proof[0][1])
    assert not verify_inclusion(leaves[5], proof, root)


def test_proof_rejects_a_flipped_sibling_side() -> None:
    leaves = _leaves(16)
    root = merkle_root(leaves)
    proof = [(sibling, not is_left) for sibling, is_left in _build_proof(leaves, 5)]
    assert not verify_inclusion(leaves[5], proof, root)


def test_proof_from_one_block_does_not_verify_against_another() -> None:
    leaves = _leaves(16)
    other_root = merkle_root(_leaves(16)[::-1])
    assert not verify_inclusion(leaves[3], _build_proof(leaves, 3), other_root)


# --------------------------------------------------------------------------- #
# Block hashing                                                                #
# --------------------------------------------------------------------------- #

def test_block_hash_covers_every_input() -> None:
    prev, root = _leaves(2)
    base = block_hash(prev, root, 5, 100)
    assert block_hash(hashlib.sha256(b"x").digest(), root, 5, 100) != base
    assert block_hash(prev, hashlib.sha256(b"x").digest(), 5, 100) != base
    assert block_hash(prev, root, 6, 100) != base
    assert block_hash(prev, root, 5, 101) != base


def test_sequence_and_count_cannot_be_confused() -> None:
    """A naive concatenation would let (seq=1, count=23) and (seq=12, count=3)
    hash identically."""
    prev, root = _leaves(2)
    assert block_hash(prev, root, 1, 23) != block_hash(prev, root, 12, 3)


# --------------------------------------------------------------------------- #
# Reporting                                                                    #
# --------------------------------------------------------------------------- #

def test_report_is_intact_only_with_no_findings() -> None:
    assert VerificationReport(10, 2, 0, []).intact
    assert not VerificationReport(10, 2, 0, [Finding("event_modified", "x")]).intact


def test_finding_renders_its_location() -> None:
    assert "block 3" in str(Finding("broken_link", "mismatch", sequence_number=3))
    assert "event abc" in str(Finding("event_modified", "mismatch", event_id="abc"))
