"""Sink behaviour: dead-letter spooling and the dry-run path."""

from __future__ import annotations

import json
from pathlib import Path

from forensics.common.config import KafkaSettings
from forensics.common.kafka import DeadLetterSpool, KafkaSink, StdoutSink, build_sink


def test_stdout_sink_emits_parseable_json(capsys) -> None:
    sink = StdoutSink("logs.raw")
    sink.send(key="web-01", value=json.dumps({"a": 1}), headers={"schema_version": "1.0.0"})
    line = json.loads(capsys.readouterr().out.strip())
    assert line == {
        "topic": "logs.raw",
        "key": "web-01",
        "headers": {"schema_version": "1.0.0"},
        "value": {"a": 1},
    }
    assert sink.stats.produced == 1


def test_spool_appends_one_json_line_per_record(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dlq.jsonl"
    spool = DeadLetterSpool(str(path))
    spool.write(key="k1", value='{"x":1}', reason="broker down")
    spool.write(key="k2", value='{"x":2}', reason="timeout")
    spool.close()

    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["key"] == "k1"
    assert first["reason"] == "broker down"
    # Payload is stored verbatim so it can be replayed byte-for-byte.
    assert json.loads(first["payload"]) == {"x": 1}


def test_spool_survives_an_unwritable_path(capsys) -> None:
    """A read-only mount must not crash the producer at construction time."""
    spool = DeadLetterSpool("/proc/forensics-not-writable/dlq.jsonl")
    spool.write(key="k", value="{}", reason="test")  # must not raise
    spool.close()


def test_build_sink_honours_dry_run(tmp_path: Path) -> None:
    settings = KafkaSettings(
        bootstrap_servers="localhost:9092",
        client_id="test",
        raw_logs_topic="logs.raw",
        dlq_topic="logs.raw.dlq",
    )
    sink = build_sink(settings, dry_run=True, spool_path=str(tmp_path / "dlq.jsonl"))
    assert isinstance(sink, StdoutSink)


def test_librdkafka_config_preserves_durability() -> None:
    settings = KafkaSettings(
        bootstrap_servers="b:9092",
        client_id="test",
        raw_logs_topic="logs.raw",
        dlq_topic="logs.raw.dlq",
    )
    config = KafkaSink._build_config(settings)
    assert config["acks"] == "all"
    assert config["enable.idempotence"] is True
    assert config["bootstrap.servers"] == "b:9092"
