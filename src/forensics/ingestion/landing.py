"""Projection of a :class:`LogEvent` onto the landing-table row shape.

``evidence.raw_events`` is written by the Spark JDBC sink, which writes by
column name. This module produces the same shape from a ``LogEvent`` directly,
so evidence can be loaded without a Kafka broker or a Spark cluster — used by
``scripts/seed_evidence.py`` and by the database test suite.

The column list mirrors ``forensics.streaming.normalize.flatten()`` exactly. It
lives here, in one place, rather than being retyped by every caller that needs
it: a column added to the flattened frame has to be added here too, and a single
definition makes that a one-line change instead of a hunt.
"""

from __future__ import annotations

from typing import Any

from forensics.ingestion.schemas import LogEvent

#: Landing-table columns, in the order :func:`to_raw_row` emits them.
RAW_COLUMNS: tuple[str, ...] = (
    "event_id",
    "event_time",
    "ingested_at",
    "category",
    "action",
    "outcome",
    "severity",
    "message",
    "dataset",
    "schema_version",
    "host_name",
    "host_ip",
    "host_os_family",
    "user_name",
    "user_uid",
    "user_domain",
    "process_pid",
    "process_name",
    "process_executable",
    "process_command_line",
    "process_parent_name",
    "process_parent_pid",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "transport",
    "bytes_sent",
    "bytes_received",
    "direction",
    "eval_is_anomaly",
    "eval_scenario",
    "eval_campaign_id",
    "eval_step",
    "kafka_topic",
    "kafka_partition",
    "kafka_offset",
)


def to_raw_row(
    event: LogEvent,
    offset: int = 0,
    *,
    topic: str = "logs.raw",
    partition: int = 0,
) -> tuple[Any, ...]:
    """Flatten one event into a landing-table row.

    ``ingested_at`` is set to the event time rather than "now". Seeded data is
    meant to look like it arrived when it happened; using wall-clock time would
    put every backfilled event in the current minute and make any time-based
    query over the seeded set meaningless.
    """
    network, process, user = event.network, event.process, event.user
    truth = event.labels.get("ground_truth") or {}

    return (
        event.event_id,
        event.timestamp,
        event.timestamp,
        str(event.category),
        event.action,
        str(event.outcome),
        event.severity,
        event.message,
        event.dataset,
        event.schema_version,
        event.host.name,
        event.host.ip,
        event.host.os_family,
        user.name if user else None,
        user.id if user else None,
        user.domain if user else None,
        process.pid if process else None,
        process.name if process else None,
        process.executable if process else None,
        process.command_line if process else None,
        process.parent_name if process else None,
        process.parent_pid if process else None,
        network.source_ip if network else None,
        network.source_port if network else None,
        network.destination_ip if network else None,
        network.destination_port if network else None,
        network.protocol if network else None,
        network.transport if network else None,
        network.bytes_sent if network else None,
        network.bytes_received if network else None,
        network.direction if network else None,
        truth.get("is_anomaly"),
        truth.get("scenario"),
        truth.get("campaign_id"),
        truth.get("step"),
        topic,
        partition,
        offset,
    )


def copy_statement(table: str = "evidence.raw_events") -> str:
    """``COPY`` statement matching :data:`RAW_COLUMNS`."""
    return f"COPY {table} ({', '.join(RAW_COLUMNS)}) FROM STDIN"
