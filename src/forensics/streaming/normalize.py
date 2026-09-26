"""Parsing, validation and flattening of the raw Kafka feed.

Every function here is a pure ``DataFrame -> DataFrame`` transform. Keeping the
logic out of the streaming wiring in :mod:`forensics.streaming.job` means it can
be tested against static DataFrames — the DataFrame API is identical in batch
and streaming, so a batch test genuinely exercises the streaming code path.

The pipeline is deliberately split into *parse → validate → route → flatten*
rather than one expression, so a record that fails can be dead-lettered with a
specific reason instead of vanishing into a null column.
"""

from __future__ import annotations

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F

from forensics.streaming.schema import (
    CORRUPT_RECORD_FIELD,
    MAX_SEVERITY,
    MIN_SEVERITY,
    PARSE_SCHEMA,
    TIMESTAMP_FORMAT,
    VALID_CATEGORIES,
    VALID_OUTCOMES,
)

#: Columns carried from the Kafka source for provenance. An analyst asking
#: "where did this row come from?" must be able to point at a topic/partition/
#: offset, and the Phase 4 ledger chains over them.
KAFKA_METADATA_COLUMNS = ("topic", "partition", "offset", "timestamp")


def parse_raw(df: DataFrame) -> DataFrame:
    """Decode the Kafka payload and parse it against the declared schema.

    PERMISSIVE mode is used deliberately: FAILFAST would abort the whole
    micro-batch on one bad record, which is precisely the outage a dead-letter
    queue exists to prevent. The corrupt payload lands in
    ``CORRUPT_RECORD_FIELD`` instead, and :func:`validate` routes it.
    """
    return df.select(
        F.col("key").cast("string").alias("kafka_key"),
        F.col("value").cast("string").alias("raw_value"),
        F.col("topic").alias("kafka_topic"),
        F.col("partition").alias("kafka_partition"),
        F.col("offset").alias("kafka_offset"),
        F.col("timestamp").alias("kafka_timestamp"),
        F.from_json(
            F.col("value").cast("string"),
            PARSE_SCHEMA,
            {"mode": "PERMISSIVE", "columnNameOfCorruptRecord": CORRUPT_RECORD_FIELD},
        ).alias("event"),
    )


def _validation_error() -> Column:
    """First failing validation rule, or null when the record is acceptable.

    Ordered most-fundamental first so the reported reason is the root cause:
    there is no point complaining about a severity range on a record that is
    not valid JSON.
    """
    event = F.col("event")
    parsed_time = F.try_to_timestamp(event["timestamp"], F.lit(TIMESTAMP_FORMAT))

    return (
        F.when(F.col("raw_value").isNull(), F.lit("empty_payload"))
        .when(event.isNull(), F.lit("malformed_json"))
        # PERMISSIVE mode signals corruption here, not with a null struct.
        .when(event[CORRUPT_RECORD_FIELD].isNotNull(), F.lit("malformed_json"))
        .when(
            event["event_id"].isNull() | (F.length(F.trim(event["event_id"])) == 0),
            F.lit("missing_event_id"),
        )
        .when(event["timestamp"].isNull(), F.lit("missing_timestamp"))
        .when(parsed_time.isNull(), F.lit("unparseable_timestamp"))
        .when(
            event["host"].isNull() | event["host"]["name"].isNull(),
            F.lit("missing_host_name"),
        )
        .when(event["category"].isNull(), F.lit("missing_category"))
        .when(
            ~event["category"].isin(*VALID_CATEGORIES),
            F.lit("unknown_category"),
        )
        .when(
            event["outcome"].isNotNull() & ~event["outcome"].isin(*VALID_OUTCOMES),
            F.lit("unknown_outcome"),
        )
        .when(
            event["severity"].isNotNull()
            & ~event["severity"].between(MIN_SEVERITY, MAX_SEVERITY),
            F.lit("severity_out_of_range"),
        )
        .otherwise(F.lit(None).cast("string"))
    )


def validate(df: DataFrame) -> DataFrame:
    """Attach a ``validation_error`` column (null == the record is good)."""
    return df.withColumn("validation_error", _validation_error())


def split_valid_invalid(df: DataFrame) -> tuple[DataFrame, DataFrame]:
    """Partition a validated DataFrame into (accepted, rejected)."""
    return (
        df.filter(F.col("validation_error").isNull()),
        df.filter(F.col("validation_error").isNotNull()),
    )


def flatten(df: DataFrame) -> DataFrame:
    """Flatten the nested ECS event into the normalised analytic row.

    Nested structs are convenient on the wire and awkward in SQL, in a feature
    vector and in a relational sink. Flattening once, here, means neither the
    feature code nor the JDBC writer has to know the wire shape.
    """
    event = F.col("event")
    network = event["network"]
    process = event["process"]
    user = event["user"]

    return df.select(
        event["event_id"].alias("event_id"),
        # The authoritative event-time column: watermarks and windows key off
        # this, never off kafka_timestamp (which is ingest time and would make
        # a backfill look like a live burst).
        F.try_to_timestamp(event["timestamp"], F.lit(TIMESTAMP_FORMAT)).alias("event_time"),
        F.col("kafka_timestamp").alias("ingested_at"),
        event["category"].alias("category"),
        event["action"].alias("action"),
        event["outcome"].alias("outcome"),
        event["severity"].cast("int").alias("severity"),
        event["message"].alias("message"),
        event["dataset"].alias("dataset"),
        event["schema_version"].alias("schema_version"),
        # Host
        event["host"]["name"].alias("host_name"),
        event["host"]["ip"].alias("host_ip"),
        event["host"]["os_family"].alias("host_os_family"),
        # User
        user["name"].alias("user_name"),
        user["id"].cast("int").alias("user_uid"),
        user["domain"].alias("user_domain"),
        # Process
        process["pid"].cast("int").alias("process_pid"),
        process["name"].alias("process_name"),
        process["executable"].alias("process_executable"),
        process["command_line"].alias("process_command_line"),
        process["parent_name"].alias("process_parent_name"),
        process["parent_pid"].cast("int").alias("process_parent_pid"),
        # Network
        network["source_ip"].alias("source_ip"),
        network["source_port"].cast("int").alias("source_port"),
        network["destination_ip"].alias("destination_ip"),
        network["destination_port"].cast("int").alias("destination_port"),
        network["protocol"].alias("protocol"),
        network["transport"].alias("transport"),
        network["bytes_sent"].cast("long").alias("bytes_sent"),
        network["bytes_received"].cast("long").alias("bytes_received"),
        network["direction"].alias("direction"),
        # Evaluation labels — carried, never featurised. See features.py.
        event["labels"]["ground_truth"]["is_anomaly"].alias("eval_is_anomaly"),
        event["labels"]["ground_truth"]["scenario"].alias("eval_scenario"),
        event["labels"]["ground_truth"]["campaign_id"].alias("eval_campaign_id"),
        event["labels"]["ground_truth"]["step"].cast("int").alias("eval_step"),
        # Provenance
        F.col("kafka_topic"),
        F.col("kafka_partition"),
        F.col("kafka_offset"),
    )


def to_dlq_records(df: DataFrame) -> DataFrame:
    """Shape rejected records for the ``logs.raw.dlq`` topic.

    The original payload is preserved byte-for-byte so the record can be
    replayed once the defect is fixed; the failure reason and source coordinates
    ride alongside it rather than being lost to a log line.
    """
    return df.select(
        F.col("kafka_key").cast("binary").alias("key"),
        F.to_json(
            F.struct(
                F.col("validation_error").alias("error"),
                F.col("kafka_topic").alias("source_topic"),
                F.col("kafka_partition").alias("source_partition"),
                F.col("kafka_offset").alias("source_offset"),
                F.current_timestamp().alias("rejected_at"),
                F.col("raw_value").alias("payload"),
            )
        )
        .cast("binary")
        .alias("value"),
    )


def to_normalized_records(df: DataFrame) -> DataFrame:
    """Shape normalised rows for the ``logs.normalized`` topic.

    Keyed by ``host_name`` for the same reason the raw topic is: downstream
    per-host stateful work stays partition-local and ordered.
    """
    return df.select(
        F.col("host_name").cast("binary").alias("key"),
        F.to_json(F.struct(*df.columns)).cast("binary").alias("value"),
    )


def normalize_stream(df: DataFrame) -> tuple[DataFrame, DataFrame]:
    """Full raw → (normalised, rejected) pipeline."""
    validated = validate(parse_raw(df))
    accepted, rejected = split_valid_invalid(validated)
    return flatten(accepted), rejected
