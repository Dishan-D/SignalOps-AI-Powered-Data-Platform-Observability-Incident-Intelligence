#!/usr/bin/env python3
"""Publish a controlled burst of invalid events to ``logs.raw``.

For the SignalOps data-quality demonstration. Each record starts as a real
generator event and has exactly one defect applied, chosen so that it fails a
specific rule in ``forensics.streaming.normalize._validation_error``:

    unknown_category       category = "telemetry_v2"
    severity_out_of_range  severity = 11
    unparseable_timestamp  timestamp = "23/10/2026 10:00"
    malformed_json         payload truncated mid-object

Records carry an ``x-signalops-demo: true`` header and are otherwise ordinary
Kafka records, so they follow the pipeline's real error path (Spark -> DLQ).

    python scripts/inject_bad_events.py --count 400
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from forensics.ingestion.generators import TelemetryGenerator  # noqa: E402

DEFECTS = ("unknown_category", "severity_out_of_range", "unparseable_timestamp", "malformed_json")
MAX_COUNT = 10_000


def corrupt(event: dict, defect: str) -> str:
    if defect == "unknown_category":
        event["category"] = "telemetry_v2"
    elif defect == "severity_out_of_range":
        event["severity"] = 11
    elif defect == "unparseable_timestamp":
        event["timestamp"] = "23/10/2026 10:00"
    text = json.dumps(event, separators=(",", ":"))
    return text[: len(text) // 2] if defect == "malformed_json" else text


def build(count: int, defects: tuple[str, ...], seed: int) -> list[tuple[str, str]]:
    generator = TelemetryGenerator(host_count=6, user_count=10, anomaly_rate=0.0, seed=seed)
    records: list[tuple[str, str]] = []
    while len(records) < count:
        for event in generator.next_events():
            if len(records) >= count:
                break
            body = json.loads(event.to_json())
            defect = defects[len(records) % len(defects)]
            records.append((body.get("host", {}).get("name", "demo"), corrupt(body, defect)))
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--count", type=int, default=400)
    parser.add_argument("--defects", default=",".join(DEFECTS),
                        help=f"comma-separated subset of: {', '.join(DEFECTS)}")
    parser.add_argument("--bootstrap", default="localhost:29092")
    parser.add_argument("--topic", default="logs.raw")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--dry-run", action="store_true", help="print records instead of publishing")
    args = parser.parse_args()

    if not 1 <= args.count <= MAX_COUNT:
        parser.error(f"--count must be within 1..{MAX_COUNT}")
    defects = tuple(d.strip() for d in args.defects.split(",") if d.strip())
    unknown = set(defects) - set(DEFECTS)
    if unknown or not defects:
        parser.error(f"unknown defects: {', '.join(sorted(unknown)) or '(none given)'}")

    records = build(args.count, defects, args.seed)
    if args.dry_run:
        for key, value in records[:10]:
            print(key, value[:160])
        print(f"... {len(records)} records (dry run)")
        return 0

    from confluent_kafka import Producer

    failures: list[str] = []
    producer = Producer({"bootstrap.servers": args.bootstrap, "client.id": "signalops-demo-injector",
                         "enable.idempotence": True, "acks": "all"})

    def report(err, _msg) -> None:  # type: ignore[no-untyped-def]
        if err is not None:
            failures.append(str(err))

    for key, value in records:
        producer.produce(args.topic, key=key.encode(), value=value.encode(),
                         headers={"x-signalops-demo": b"true"}, on_delivery=report)
        producer.poll(0)
    remaining = producer.flush(30)
    if remaining or failures:
        print(f"delivery incomplete: {remaining} unflushed, {len(failures)} failed "
              f"({failures[:1]})", file=sys.stderr)
        return 1
    mix = {d: sum(1 for i in range(args.count) if defects[i % len(defects)] == d) for d in defects}
    print(json.dumps({"published": args.count, "topic": args.topic, "defects": mix}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
