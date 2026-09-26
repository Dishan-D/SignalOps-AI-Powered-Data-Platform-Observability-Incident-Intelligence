"""Spark Structured Streaming normalisation job — Phase 2 entrypoint.

    logs.raw ──► parse ──► validate ──┬── valid ──► flatten ──┬─► logs.normalized
                                      │                       ├─► features (Kafka)
                                      │                       └─► PostgreSQL (optional)
                                      └── invalid ─────────────► logs.raw.dlq

Run it against the Compose stack:

    spark-submit \
      --packages org.apache.spark:spark-sql-kafka-0-10_2.13:4.0.0 \
      src/forensics/streaming/job.py

Each output is its own streaming query with its own checkpoint directory.
Checkpoints are what make the job restartable: Spark records the Kafka offsets
it has committed alongside the aggregation state, so a restart resumes exactly
where it stopped rather than replaying or skipping.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.streaming import StreamingQuery

from forensics.common.config import AppSettings, ConfigError, KafkaSettings, SparkSettings
from forensics.common.logging import configure_logging, get_logger
from forensics.streaming.features import (
    assert_no_label_leakage,
    host_activity_features,
    peer_connection_features,
)
from forensics.streaming.normalize import (
    normalize_stream,
    to_dlq_records,
    to_normalized_records,
)

SERVICE_NAME = "spark-normalizer"

logger = get_logger(__name__, component="streaming")


def build_session(spark_cfg: SparkSettings) -> SparkSession:
    """Create the SparkSession.

    ``shuffle.partitions`` defaults to 200, which on a laptop-sized stream means
    200 mostly-empty tasks per micro-batch and scheduling overhead that dwarfs
    the actual work. It is sized to the deployment instead.
    """
    return (
        SparkSession.builder.appName(spark_cfg.app_name)
        .master(spark_cfg.master)
        .config("spark.sql.shuffle.partitions", spark_cfg.shuffle_partitions)
        .config("spark.sql.session.timeZone", "UTC")
        # Fail fast on ambiguous datetime parsing rather than silently
        # producing nulls under the legacy calendar rules.
        .config("spark.sql.legacy.timeParserPolicy", "CORRECTED")
        # Streaming state is retained across restarts; compacting the log keeps
        # checkpoint directories from growing without bound.
        .config("spark.sql.streaming.minBatchesToRetain", "10")
        .getOrCreate()
    )


def read_raw_stream(
    spark: SparkSession, kafka_cfg: KafkaSettings, spark_cfg: SparkSettings
) -> DataFrame:
    """Subscribe to the raw telemetry topic."""
    return (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", kafka_cfg.bootstrap_servers)
        .option("subscribe", kafka_cfg.raw_logs_topic)
        .option("startingOffsets", spark_cfg.starting_offsets)
        # Bounds the size of a micro-batch. Without it, a job restarting against
        # a large backlog tries to process the whole topic in one batch and
        # OOMs — the classic "it worked until it fell behind" failure.
        .option("maxOffsetsPerTrigger", spark_cfg.max_offsets_per_trigger)
        # A topic losing data under us (retention, deletion) should be loud.
        .option("failOnDataLoss", "true")
        .load()
    )


def _write_kafka(
    df: DataFrame,
    *,
    kafka_cfg: KafkaSettings,
    topic: str,
    checkpoint: str,
    query_name: str,
    trigger_interval: str,
    output_mode: str = "append",
) -> StreamingQuery:
    """Attach a Kafka sink to a stream."""
    return (
        df.writeStream.format("kafka")
        .option("kafka.bootstrap.servers", kafka_cfg.bootstrap_servers)
        .option("topic", topic)
        .option("checkpointLocation", checkpoint)
        .outputMode(output_mode)
        .queryName(query_name)
        .trigger(processingTime=trigger_interval)
        .start()
    )


def _jdbc_batch_writer(
    spark_cfg: SparkSettings, table: str
) -> Callable[[DataFrame, int], None]:
    """Return a ``foreachBatch`` function writing a micro-batch over JDBC.

    Structured Streaming has no first-class JDBC sink, so ``foreachBatch`` is
    the supported route: each micro-batch is an ordinary DataFrame and gets an
    ordinary batch write.

    The write is ``append`` only. Postgres enforces the same thing at the grant
    level for the ledger schema — evidence is never updated in place.
    """

    def write_batch(batch_df: DataFrame, batch_id: int) -> None:
        count = batch_df.count()
        if count == 0:
            return
        (
            batch_df.write.format("jdbc")
            .option("url", spark_cfg.postgres_url)
            .option("dbtable", table)
            .option("user", spark_cfg.postgres_user)
            .option("password", spark_cfg.postgres_password)
            .option("driver", "org.postgresql.Driver")
            .option("batchsize", spark_cfg.postgres_batch_size)
            # Rewriting inserts as multi-row statements is the single biggest
            # JDBC throughput win here.
            .option("reWriteBatchedInserts", "true")
            .mode("append")
            .save()
        )
        logger.info(
            "Wrote micro-batch to PostgreSQL",
            extra={"batch_id": batch_id, "rows": count, "table": table},
        )

    return write_batch


def start_queries(
    spark: SparkSession,
    kafka_cfg: KafkaSettings,
    spark_cfg: SparkSettings,
) -> list[StreamingQuery]:
    """Build the pipeline and start every sink."""
    raw = read_raw_stream(spark, kafka_cfg, spark_cfg)
    normalized, rejected = normalize_stream(raw)

    checkpoint_root = spark_cfg.checkpoint_location.rstrip("/")
    queries: list[StreamingQuery] = []

    # 1. Normalised events.
    queries.append(
        _write_kafka(
            to_normalized_records(normalized),
            kafka_cfg=kafka_cfg,
            topic="logs.normalized",
            checkpoint=f"{checkpoint_root}/normalized",
            query_name="normalized-events",
            trigger_interval=spark_cfg.trigger_interval,
        )
    )

    # 2. Dead letters. Same trigger, separate checkpoint: a poison-message storm
    #    must not be able to stall the healthy path.
    queries.append(
        _write_kafka(
            to_dlq_records(rejected),
            kafka_cfg=kafka_cfg,
            topic=kafka_cfg.dlq_topic,
            checkpoint=f"{checkpoint_root}/dlq",
            query_name="dead-letters",
            trigger_interval=spark_cfg.trigger_interval,
        )
    )

    # 3. Windowed features. Append mode emits a window only once the watermark
    #    has passed its end, so each window is written exactly once — at the
    #    cost of watermark-delay latency.
    host_features = host_activity_features(
        normalized,
        watermark_delay=spark_cfg.watermark_delay,
        window_duration=spark_cfg.window_duration,
        window_slide=spark_cfg.window_slide,
    )
    assert_no_label_leakage(host_features)
    queries.append(
        _write_kafka(
            host_features.select(
                F.col("host_name").cast("binary").alias("key"),
                F.to_json(F.struct("*")).cast("binary").alias("value"),
            ),
            kafka_cfg=kafka_cfg,
            topic="features.host_activity",
            checkpoint=f"{checkpoint_root}/features-host",
            query_name="host-activity-features",
            trigger_interval=spark_cfg.trigger_interval,
        )
    )

    peer_features = peer_connection_features(
        normalized, watermark_delay=spark_cfg.watermark_delay
    )
    assert_no_label_leakage(peer_features)
    queries.append(
        _write_kafka(
            peer_features.select(
                F.col("host_name").cast("binary").alias("key"),
                F.to_json(F.struct("*")).cast("binary").alias("value"),
            ),
            kafka_cfg=kafka_cfg,
            topic="features.peer_connections",
            checkpoint=f"{checkpoint_root}/features-peer",
            query_name="peer-connection-features",
            trigger_interval=spark_cfg.trigger_interval,
        )
    )

    # 4. Optional evidence store. Off by default so the streaming tier can run
    #    before the Phase 3 schema is deployed.
    if spark_cfg.postgres_enabled:
        queries.append(
            normalized.writeStream.foreachBatch(
                _jdbc_batch_writer(spark_cfg, "evidence.raw_events")
            )
            .option("checkpointLocation", f"{checkpoint_root}/postgres")
            .queryName("evidence-store")
            .trigger(processingTime=spark_cfg.trigger_interval)
            .start()
        )

    return queries


def main() -> int:
    try:
        settings = AppSettings.from_env(SERVICE_NAME)
        spark_cfg = SparkSettings.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    configure_logging(
        service=settings.service_name,
        environment=settings.environment,
        level=settings.log_level,
    )

    spark = build_session(spark_cfg)
    spark.sparkContext.setLogLevel("WARN")

    logger.info(
        "Starting streaming job",
        extra={
            "master": spark_cfg.master,
            "source_topic": settings.kafka.raw_logs_topic,
            "checkpoint": spark_cfg.checkpoint_location,
            "starting_offsets": spark_cfg.starting_offsets,
            "postgres_sink": spark_cfg.postgres_enabled,
        },
    )

    try:
        queries = start_queries(spark, settings.kafka, spark_cfg)
        logger.info(
            "Streaming queries started",
            extra={"queries": [q.name for q in queries]},
        )
        # Returns as soon as *any* query fails, so a broken sink surfaces as a
        # non-zero exit rather than a job that looks alive but has stopped
        # producing one of its outputs.
        spark.streams.awaitAnyTermination()
    except KeyboardInterrupt:
        logger.info("Interrupted; stopping queries")
    except Exception:
        logger.critical("Streaming job failed", exc_info=True)
        return 1
    finally:
        spark.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
