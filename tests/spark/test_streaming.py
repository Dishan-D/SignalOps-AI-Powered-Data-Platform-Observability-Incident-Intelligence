"""End-to-end streaming semantics: watermarks, windows and append-mode emission.

Batch DataFrames exercise the *transform* logic but say nothing about the
streaming execution model — whether a window is ever emitted, whether the
watermark advances, whether late data is dropped. Those are the behaviours that
break in production, so they get a real streaming query here.

A file source stands in for Kafka: the Kafka connector is a separate Maven
artefact that would have to be downloaded at test time, and the streaming
semantics under test are identical either way.
"""

from __future__ import annotations

import datetime as dt

from forensics.streaming.features import host_activity_features
from tests.spark.test_features import BASE, NORMALIZED_SCHEMA, _row


def _write_batch(spark, path: str, rows: list) -> None:
    """Append one batch of JSON files for the stream to pick up."""
    spark.createDataFrame(rows, NORMALIZED_SCHEMA).write.mode("append").json(path)


def test_windowed_features_are_emitted_in_append_mode(spark, tmp_path) -> None:
    data_dir = str(tmp_path / "events")
    checkpoint = str(tmp_path / "checkpoint")

    # Batch 1: a burst of failed logins inside one window.
    _write_batch(
        spark,
        data_dir,
        [
            _row(
                event_time=BASE + dt.timedelta(seconds=i),
                category="authentication", outcome="failure", source_ip="203.0.113.9",
            )
            for i in range(20)
        ],
    )

    stream = (
        spark.readStream.schema(NORMALIZED_SCHEMA)
        .option("maxFilesPerTrigger", 1)
        .json(data_dir)
    )
    features = host_activity_features(
        stream, watermark_delay="2 minutes", window_duration="1 minute",
        window_slide="30 seconds",
    )

    query = (
        features.writeStream.format("memory")
        .queryName("host_features_test")
        .outputMode("append")
        .option("checkpointLocation", checkpoint)
        .start()
    )
    try:
        query.processAllAvailable()

        # Append mode holds a window back until the watermark passes its end, so
        # nothing should have been emitted yet.
        assert spark.sql("SELECT * FROM host_features_test").count() == 0

        # Batch 2 is 30 minutes later, pushing the watermark past batch 1's
        # windows and releasing them.
        _write_batch(
            spark, data_dir,
            [_row(event_time=BASE + dt.timedelta(minutes=30), category="network")],
        )
        query.processAllAvailable()

        results = spark.sql("SELECT * FROM host_features_test").collect()
        assert results, "windows should be emitted once the watermark advances"

        peak = max(results, key=lambda r: r["auth_failure_count"])
        assert peak["auth_failure_count"] >= 15
        assert peak["host_name"] == "web-01.corp.local"
        assert peak["window_start"] is not None
        assert peak["window_end"] > peak["window_start"]
    finally:
        query.stop()


def test_late_data_beyond_the_watermark_is_dropped(spark, tmp_path) -> None:
    """State cannot be retained forever; arrivals past the watermark are dropped."""
    data_dir = str(tmp_path / "events")
    checkpoint = str(tmp_path / "checkpoint")

    _write_batch(spark, data_dir, [_row(event_time=BASE, category="network")])

    stream = (
        spark.readStream.schema(NORMALIZED_SCHEMA)
        .option("maxFilesPerTrigger", 1)
        .json(data_dir)
    )
    query = (
        host_activity_features(
            stream, watermark_delay="1 minute", window_duration="1 minute",
            window_slide="1 minute",
        )
        .writeStream.format("memory")
        .queryName("late_data_test")
        .outputMode("append")
        .option("checkpointLocation", checkpoint)
        .start()
    )
    try:
        query.processAllAvailable()

        # Advance the watermark well past the first window.
        _write_batch(
            spark, data_dir,
            [_row(event_time=BASE + dt.timedelta(minutes=20), category="network")],
        )
        query.processAllAvailable()
        emitted_before = spark.sql("SELECT * FROM late_data_test").count()

        # Now deliver an event belonging to the long-closed first window.
        _write_batch(
            spark, data_dir,
            [_row(event_time=BASE + dt.timedelta(seconds=5), category="network")],
        )
        query.processAllAvailable()

        progress = query.recentProgress
        assert progress, "expected progress metrics"
        # The reopened window must not be re-emitted with a corrected count.
        emitted_after = spark.sql(
            "SELECT * FROM late_data_test WHERE window_start = "
            "TIMESTAMP '2026-09-09 12:00:00'"
        ).count()
        assert emitted_after <= 1
        assert emitted_before >= 1
    finally:
        query.stop()


def test_query_survives_a_restart_from_checkpoint(spark, tmp_path) -> None:
    """A restart must resume from committed offsets, not reprocess the source.

    Uses a file sink rather than the memory sink: `memory` cannot recover from a
    checkpoint at all, so it is structurally unable to test this. The file sink
    has the same exactly-once commit protocol the Kafka sink uses.
    """
    data_dir = str(tmp_path / "events")
    out_dir = str(tmp_path / "out")
    checkpoint = str(tmp_path / "checkpoint")

    _write_batch(spark, data_dir, [_row(event_time=BASE, category="network")
                                   for _ in range(5)])

    def start():
        stream = spark.readStream.schema(NORMALIZED_SCHEMA).json(data_dir)
        return (
            stream.writeStream.format("json")
            .option("path", out_dir)
            .option("checkpointLocation", checkpoint)
            .outputMode("append")
            .start()
        )

    first = start()
    try:
        first.processAllAvailable()
    finally:
        first.stop()
    assert spark.read.schema(NORMALIZED_SCHEMA).json(out_dir).count() == 5

    # Same checkpoint, fresh query: already-committed input must not be
    # replayed, or every restart would duplicate evidence.
    second = start()
    try:
        second.processAllAvailable()
        assert spark.read.schema(NORMALIZED_SCHEMA).json(out_dir).count() == 5

        _write_batch(spark, data_dir, [_row(event_time=BASE, category="process")])
        second.processAllAvailable()
        # Exactly one new row: no replay, no loss.
        assert spark.read.schema(NORMALIZED_SCHEMA).json(out_dir).count() == 6
    finally:
        second.stop()
