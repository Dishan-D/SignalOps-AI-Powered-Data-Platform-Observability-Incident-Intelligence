"""Independent re-implementation of the evidence chain.

This module deliberately duplicates logic that already exists as SQL functions
in ``db/migrations/0004_evidence_ledger.sql``. That is the point.

A ledger verified only by the database that stores it proves very little: an
attacker who can rewrite rows can usually also rewrite
``ledger.verify_chain()``. A second implementation, running outside the
database and reading nothing but raw column values, is what makes the guarantee
mean something. ``tests/db/test_ledger.py`` asserts the two agree byte for byte
on real data — so a divergence in either one fails the build.

The encoding is a protocol, not an implementation detail. Changing field order,
the length prefix, the timestamp format or a domain-separation byte invalidates
every digest ever written.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

#: Domain-separation prefixes (RFC 6962 style). Without them, an internal node
#: hash could be presented as a leaf — the classic Merkle second-preimage
#: attack.
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
BLOCK_PREFIX = b"\x02"

#: Anchor for block 0's ``prev_hash``. Fixed and public: the chain must be
#: verifiable from scratch by anyone, so this is not a secret.
GENESIS_SEED = b"forensics-ledger-genesis-v1"

#: Field order is part of the protocol. It mirrors ``ledger.canonical_event``.
EVENT_FIELDS: tuple[str, ...] = (
    "event_id",
    "occurred_at",
    "ingested_at",
    "category",
    "action",
    "outcome",
    "severity",
    "message",
    "host_id",
    "user_id",
    "dataset_id",
    "process_image_id",
    "process_pid",
    "process_command_line",
    "process_parent_image_id",
    "process_parent_pid",
    "source_address_id",
    "source_port",
    "destination_address_id",
    "destination_port",
    "protocol",
    "transport",
    "bytes_sent",
    "bytes_received",
    "direction",
    "schema_version",
    "kafka_partition",
    "kafka_offset",
)

#: Fields rendered with :func:`encode_timestamp` rather than :func:`encode_field`.
TIMESTAMP_FIELDS = frozenset({"occurred_at", "ingested_at"})


def encode_field(value: Any) -> str:
    """Length-prefixed encoding of one field.

    Length-prefixed rather than delimiter-separated because ``message`` is
    attacker-influenced text: with a plain separator, a crafted log line
    containing the delimiter could shift field boundaries and make two different
    records share a canonical form. The prefix is the **byte** length, so a
    multibyte character cannot change the framing either.

    ``NULL`` encodes as length ``-1``, which no real value can produce, keeping
    it distinct from the empty string.
    """
    if value is None:
        return "-1:"
    text = _render(value)
    return f"{len(text.encode('utf-8'))}:{text}"


def _render(value: Any) -> str:
    """Render a value the way PostgreSQL's ``::TEXT`` cast would."""
    if isinstance(value, bool):
        # Guard: bool is a subclass of int, and Postgres renders it 't'/'f'.
        # No boolean is in EVENT_FIELDS today; fail loudly rather than silently
        # disagree with the SQL side if one is ever added.
        raise TypeError("boolean fields are not part of the canonical encoding")
    if isinstance(value, (int, uuid.UUID)):
        return str(value)
    return str(value)


def encode_timestamp(value: dt.datetime | None) -> str:
    """UTC, microsecond precision, locale-independent.

    Matches ``to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')``.
    Any session- or locale-dependent rendering would make a digest depend on who
    computed it.
    """
    if value is None:
        return "-1:"
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    moment = value.astimezone(dt.timezone.utc)
    return encode_field(moment.strftime("%Y-%m-%dT%H:%M:%S.%f"))


def canonical_event(row: dict[str, Any]) -> str:
    """Canonical serialisation of one evidence row."""
    parts = []
    for field in EVENT_FIELDS:
        value = row.get(field)
        if field in TIMESTAMP_FIELDS:
            parts.append(encode_timestamp(value))
        else:
            parts.append(encode_field(value))
    return "|".join(parts)


def leaf_hash(canonical: str) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + canonical.encode("utf-8")).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def event_digest(row: dict[str, Any]) -> bytes:
    """SHA-256 leaf digest of an evidence row."""
    return leaf_hash(canonical_event(row))


def genesis_hash() -> bytes:
    return hashlib.sha256(GENESIS_SEED).digest()


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Merkle root over ordered leaf digests.

    An odd node is promoted **unchanged**, never duplicated. Duplicating it (the
    Bitcoin construction) lets two different leaf sets produce an identical root
    — CVE-2012-2459 — which in this context would mean a forged block passing
    verification.
    """
    if not leaves:
        return hashlib.sha256(LEAF_PREFIX).digest()

    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
        for index in range(0, len(level), 2):
            if index + 1 < len(level):
                nxt.append(node_hash(level[index], level[index + 1]))
            else:
                nxt.append(level[index])
        level = nxt
    return level[0]


def block_hash(
    prev_hash: bytes, root: bytes, sequence_number: int, event_count: int
) -> bytes:
    payload = f"{sequence_number}:{event_count}".encode()
    return hashlib.sha256(BLOCK_PREFIX + prev_hash + root + payload).digest()


def verify_inclusion(
    digest: bytes, proof: Sequence[tuple[bytes, bool]], expected_root: bytes
) -> bool:
    """Check an inclusion proof.

    ``proof`` is a sequence of ``(sibling, sibling_is_left)`` from leaf upward,
    as produced by ``ledger.inclusion_proof``. Proving one event belongs to a
    sealed block needs only O(log n) siblings and discloses no other event —
    which matters when evidence is handed to a third party entitled to one
    record and not the rest.
    """
    current = digest
    for sibling, sibling_is_left in proof:
        current = (
            node_hash(sibling, current) if sibling_is_left else node_hash(current, sibling)
        )
    return current == expected_root


# --------------------------------------------------------------------------- #
# Findings                                                                     #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class Finding:
    """One integrity violation."""

    kind: str
    detail: str
    event_id: str | None = None
    sequence_number: int | None = None

    def __str__(self) -> str:
        where = ""
        if self.sequence_number is not None:
            where = f" block {self.sequence_number}"
        elif self.event_id:
            where = f" event {self.event_id}"
        return f"{self.kind}{where}: {self.detail}"


@dataclass(frozen=True, slots=True)
class VerificationReport:
    events_checked: int
    blocks_checked: int
    unsealed_events: int
    findings: list[Finding]

    @property
    def intact(self) -> bool:
        return not self.findings

    def summary(self) -> str:
        status = "INTACT" if self.intact else f"COMPROMISED ({len(self.findings)} findings)"
        return (
            f"{status} — {self.events_checked} events, {self.blocks_checked} blocks, "
            f"{self.unsealed_events} unsealed"
        )
