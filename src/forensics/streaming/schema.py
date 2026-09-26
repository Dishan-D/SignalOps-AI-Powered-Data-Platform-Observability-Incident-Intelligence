"""Explicit Spark schema for the ``logs.raw`` wire contract.

The schema is declared, never inferred. Schema inference requires a scan, which
a streaming source cannot do, and it silently changes shape when the input data
changes — exactly the failure mode you do not want in an evidence pipeline. The
cost is that this file must be kept in step with
:mod:`forensics.ingestion.schemas`; ``tests/spark/test_schema_drift.py`` fails
the build if the two diverge.

Unknown JSON keys are dropped by ``from_json`` against a declared schema. That
is intentional for everything except ``labels``, where it means a new label key
needs a schema change to survive — noted in :data:`LABELS_SCHEMA`.
"""

from __future__ import annotations

from pyspark.sql.types import (
    BooleanType,
    IntegerType,
    LongType,
    StringType,
    StructField,
    StructType,
)

# ``host`` is the only mandatory nested object; the rest are category-dependent.
HOST_SCHEMA = StructType(
    [
        StructField("name", StringType(), nullable=False),
        StructField("ip", StringType(), nullable=True),
        StructField("os_family", StringType(), nullable=True),
    ]
)

USER_SCHEMA = StructType(
    [
        StructField("name", StringType(), nullable=True),
        StructField("id", IntegerType(), nullable=True),
        StructField("domain", StringType(), nullable=True),
    ]
)

PROCESS_SCHEMA = StructType(
    [
        StructField("pid", IntegerType(), nullable=True),
        StructField("name", StringType(), nullable=True),
        StructField("executable", StringType(), nullable=True),
        StructField("command_line", StringType(), nullable=True),
        StructField("parent_name", StringType(), nullable=True),
        StructField("parent_pid", IntegerType(), nullable=True),
    ]
)

# Byte counters are LongType: a single large transfer overflows a 32-bit int,
# and the exfiltration scenario deliberately produces ~900 MB flows.
NETWORK_SCHEMA = StructType(
    [
        StructField("source_ip", StringType(), nullable=True),
        StructField("source_port", IntegerType(), nullable=True),
        StructField("destination_ip", StringType(), nullable=True),
        StructField("destination_port", IntegerType(), nullable=True),
        StructField("protocol", StringType(), nullable=True),
        StructField("transport", StringType(), nullable=True),
        StructField("bytes_sent", LongType(), nullable=True),
        StructField("bytes_received", LongType(), nullable=True),
        StructField("direction", StringType(), nullable=True),
    ]
)

#: Evaluation ground truth emitted by the synthetic producer.
#:
#: This is the label set for scoring the Phase 3 detector. It is carried through
#: normalisation in a dedicated column and **excluded from every feature**; see
#: :mod:`forensics.streaming.features`.
GROUND_TRUTH_SCHEMA = StructType(
    [
        StructField("is_anomaly", BooleanType(), nullable=True),
        StructField("scenario", StringType(), nullable=True),
        StructField("campaign_id", StringType(), nullable=True),
        StructField("step", IntegerType(), nullable=True),
    ]
)

#: Only ``ground_truth`` is typed. A new label key added by a producer will be
#: dropped here until it is declared — the deliberate trade for an explicit
#: schema over inference.
LABELS_SCHEMA = StructType(
    [StructField("ground_truth", GROUND_TRUTH_SCHEMA, nullable=True)]
)

#: Top-level schema of a ``logs.raw`` record value.
RAW_EVENT_SCHEMA = StructType(
    [
        StructField("event_id", StringType(), nullable=False),
        StructField("timestamp", StringType(), nullable=False),
        StructField("category", StringType(), nullable=False),
        StructField("action", StringType(), nullable=True),
        StructField("outcome", StringType(), nullable=True),
        StructField("severity", IntegerType(), nullable=True),
        StructField("message", StringType(), nullable=True),
        StructField("host", HOST_SCHEMA, nullable=False),
        StructField("dataset", StringType(), nullable=True),
        StructField("user", USER_SCHEMA, nullable=True),
        StructField("process", PROCESS_SCHEMA, nullable=True),
        StructField("network", NETWORK_SCHEMA, nullable=True),
        StructField("labels", LABELS_SCHEMA, nullable=True),
        StructField("schema_version", StringType(), nullable=True),
    ]
)

#: Column ``from_json`` parks an unparseable payload in.
#:
#: Necessary because PERMISSIVE mode (the default) returns a struct with every
#: field null for corrupt input rather than a null struct. Without this column
#: there is no way to tell "the JSON was garbage" from "the JSON was fine but
#: omitted event_id", and the DLQ would report the wrong reason.
CORRUPT_RECORD_FIELD = "_corrupt_record"

#: Schema actually handed to ``from_json``: the wire schema plus the corrupt
#: record column that PERMISSIVE mode populates.
PARSE_SCHEMA = StructType(
    [*RAW_EVENT_SCHEMA.fields, StructField(CORRUPT_RECORD_FIELD, StringType(), nullable=True)]
)

#: Timestamp format emitted by ``LogEvent.format_timestamp`` —
#: ``2026-09-09T06:53:44.532+00:00``. Declared explicitly so a malformed value
#: becomes a DLQ record rather than a silently-null column.
TIMESTAMP_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"

#: Categories the pipeline understands. Anything else is routed to the DLQ:
#: an unrecognised category means the producer and consumer disagree about the
#: contract, which is a bug to surface, not to average over.
VALID_CATEGORIES = ("authentication", "process", "network", "file")

VALID_OUTCOMES = ("success", "failure", "unknown")

#: Syslog severity bounds, inclusive.
MIN_SEVERITY = 0
MAX_SEVERITY = 7
