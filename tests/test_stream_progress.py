"""Stream-progress capture (forensics.streaming.progress) and sealer verification recording.

Pure Python: no JVM, no database. The listener's Spark-facing class is covered
by the Spark suite's environment; here the parsing, buffering and SQL shape are.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from forensics.ledger.chain import Finding, VerificationReport
from forensics.ledger.sealer import record_verification
from forensics.streaming.progress import (
    INSERT_PROGRESS_SQL,
    UPSERT_QUERY_SQL,
    LifecycleEvent,
    ProgressRecorder,
    progress_row,
)

SPARK_PROGRESS = {
    "id": "q-1", "runId": "r-1", "name": "dead-letters", "timestamp": "2026-10-23T10:00:00.123Z",
    "batchId": 17, "numInputRows": 250, "inputRowsPerSecond": 25.0, "processedRowsPerSecond": "NaN",
    "durationMs": {"triggerExecution": 812, "addBatch": 700},
    "eventTime": {"watermark": "2026-10-23T09:58:00.000Z"},
    "sources": [
        {"description": "KafkaV2[Subscribe[logs.raw]]", "numInputRows": 250,
         "endOffset": {"logs.raw": {"0": 120}}, "latestOffset": {"logs.raw": {"0": 140}},
         "metrics": {"maxOffsetsBehindLatest": "20", "avgOffsetsBehindLatest": "10.0"}},
    ],
    "sink": {"description": "org.apache.spark.sql.kafka010.KafkaSink", "numOutputRows": 31},
}


def test_progress_row_maps_reported_fields() -> None:
    row = progress_row(SPARK_PROGRESS)
    assert row is not None
    assert (row.query_name, row.batch_id, row.num_input_rows) == ("dead-letters", 17, 250)
    assert row.batch_timestamp == dt.datetime(2026, 10, 23, 10, 0, 0, 123000, tzinfo=dt.timezone.utc)
    assert row.processed_rows_per_second is None  # NaN is "not reported", not zero
    assert row.max_offsets_behind_latest == 20
    assert row.sink_output_rows == 31
    assert row.trigger_execution_ms == 812
    assert row.watermark is not None


def test_unreported_sink_rows_are_null() -> None:
    row = progress_row({**SPARK_PROGRESS, "sink": {"numOutputRows": -1}})
    assert row is not None and row.sink_output_rows is None


def test_unusable_progress_is_dropped() -> None:
    assert progress_row({}) is None
    assert progress_row({**SPARK_PROGRESS, "timestamp": "yesterday"}) is None


class FakeCursor:
    def __init__(self, log: list[tuple[str, Any]], fail: bool = False) -> None:
        self.log, self.fail = log, fail

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, sql: str, params: Any = None) -> None:
        if self.fail:
            raise RuntimeError("relation ops.ledger_verifications does not exist")
        self.log.append((sql, params))


class FakeConnection:
    def __init__(self, fail: bool = False) -> None:
        self.log: list[tuple[str, Any]] = []
        self.fail = fail

    def cursor(self) -> FakeCursor:
        return FakeCursor(self.log, self.fail)

    def close(self) -> None:
        pass


def test_recorder_writes_progress_and_query_state() -> None:
    connection = FakeConnection()
    recorder = ProgressRecorder(lambda: connection, prune_every=0)
    recorder.write(progress_row(SPARK_PROGRESS))  # type: ignore[arg-type]
    recorder.write(LifecycleEvent(query_name="dead-letters", query_id="q-1", run_id="r-1",
                                  status="terminated", at=dt.datetime.now(tz=dt.timezone.utc),
                                  exception="boom" * 2000))
    sqls = [sql for sql, _ in connection.log]
    assert sqls == [INSERT_PROGRESS_SQL, UPSERT_QUERY_SQL, UPSERT_QUERY_SQL]
    assert len(connection.log[2][1]["exception"]) == 4000  # bounded


def test_recorder_queue_is_bounded_and_never_blocks() -> None:
    recorder = ProgressRecorder(lambda: FakeConnection(), capacity=3)
    row = progress_row(SPARK_PROGRESS)
    for _ in range(10):
        recorder.submit(row)  # type: ignore[arg-type]
    assert recorder.dropped == 7


def test_sealer_records_verification() -> None:
    connection = FakeConnection()
    report = VerificationReport(events_checked=10, blocks_checked=2, unsealed_events=1,
                                findings=[Finding(kind="event_modified", detail="x" * 900, event_id="e1")])
    now = dt.datetime.now(tz=dt.timezone.utc)
    assert record_verification(connection, report, started_at=now, finished_at=now) is True
    _, params = connection.log[0]
    assert params[2] is False and params[6] == 1
    findings = json.loads(params[7])
    assert findings[0]["kind"] == "event_modified" and len(findings[0]["detail"]) == 500


def test_sealer_recording_failure_does_not_raise() -> None:
    report = VerificationReport(events_checked=0, blocks_checked=0, unsealed_events=0, findings=[])
    now = dt.datetime.now(tz=dt.timezone.utc)
    assert record_verification(FakeConnection(fail=True), report, started_at=now, finished_at=now) is False
