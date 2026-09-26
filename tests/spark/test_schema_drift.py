"""The Spark schema and the producer's dataclasses must not drift apart.

The wire contract is declared twice — once as Python dataclasses the producer
serialises from, once as a Spark StructType the consumer parses with. That
duplication is deliberate (an explicit schema beats inference on a stream), but
it only stays safe if a change to one side fails the build on the other.
"""

from __future__ import annotations

from dataclasses import fields

from pyspark.sql.types import StructType

from forensics.ingestion.schemas import (
    HostFields,
    LogEvent,
    NetworkFields,
    ProcessFields,
    UserFields,
)
from forensics.streaming.schema import (
    HOST_SCHEMA,
    NETWORK_SCHEMA,
    PROCESS_SCHEMA,
    RAW_EVENT_SCHEMA,
    USER_SCHEMA,
)


def _spark_field_names(schema: StructType) -> set[str]:
    return {f.name for f in schema.fields}


def _dataclass_field_names(cls: type) -> set[str]:
    return {f.name for f in fields(cls)}


def test_top_level_fields_match() -> None:
    assert _spark_field_names(RAW_EVENT_SCHEMA) == _dataclass_field_names(LogEvent)


def test_host_fields_match() -> None:
    assert _spark_field_names(HOST_SCHEMA) == _dataclass_field_names(HostFields)


def test_user_fields_match() -> None:
    assert _spark_field_names(USER_SCHEMA) == _dataclass_field_names(UserFields)


def test_process_fields_match() -> None:
    assert _spark_field_names(PROCESS_SCHEMA) == _dataclass_field_names(ProcessFields)


def test_network_fields_match() -> None:
    assert _spark_field_names(NETWORK_SCHEMA) == _dataclass_field_names(NetworkFields)


def test_real_producer_output_parses_without_loss(spark) -> None:
    """A live event from the generator must survive the declared schema."""
    from pyspark.sql import functions as F

    from forensics.ingestion.generators import TelemetryGenerator

    generator = TelemetryGenerator(seed=77, anomaly_rate=0.5)
    payloads = []
    while len(payloads) < 300:
        payloads.extend(e.to_json() for e in generator.next_events())

    df = spark.createDataFrame([(p,) for p in payloads], "value string")
    parsed = df.select(F.from_json(F.col("value"), RAW_EVENT_SCHEMA).alias("e"))

    # No record may fail to parse, and no mandatory field may come back null.
    assert parsed.filter(F.col("e").isNull()).count() == 0
    assert parsed.filter(F.col("e")["event_id"].isNull()).count() == 0
    assert parsed.filter(F.col("e")["host"]["name"].isNull()).count() == 0
    assert parsed.filter(F.col("e")["timestamp"].isNull()).count() == 0
