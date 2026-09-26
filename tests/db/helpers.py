"""Helpers for the database test suite.

The landing-row projection lives in :mod:`forensics.ingestion.landing` and is
shared with ``scripts/seed_evidence.py`` — one definition, so a column added to
the flattened frame cannot drift between the seeder and the tests.
"""

from __future__ import annotations

from forensics.ingestion.landing import RAW_COLUMNS, copy_statement, to_raw_row
from forensics.ingestion.schemas import LogEvent

__all__ = ["RAW_COLUMNS", "generate", "land", "normalize", "to_raw_row"]


def land(conn, events, *, start_offset: int = 0) -> int:
    """COPY events into evidence.raw_events, as the Spark sink would."""
    with conn.cursor() as cur, cur.copy(copy_statement()) as copy:
        for i, event in enumerate(events, start=start_offset):
            copy.write_row(to_raw_row(event, i))
    return len(events)


def normalize(conn, batch_size: int = 20_000) -> tuple[int, int]:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM evidence.normalize_raw_events(%s)", (batch_size,))
        return cur.fetchone()


def generate(count: int, **kwargs) -> list[LogEvent]:
    from forensics.ingestion.generators import TelemetryGenerator

    generator = TelemetryGenerator(**kwargs)
    events: list[LogEvent] = []
    while len(events) < count:
        events.extend(generator.next_events())
    return events[:count]
