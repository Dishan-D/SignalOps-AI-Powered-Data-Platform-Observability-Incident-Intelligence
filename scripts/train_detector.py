#!/usr/bin/env python3
"""Train and evaluate the LogBERT anomaly detector end to end.

    python scripts/train_detector.py --epochs 30 --out artifacts/logbert

Three disjoint datasets, generated with different seeds *and* different host and
user populations so nothing leaks between them:

* **train**    — benign only. One-class training; the model never sees an attack.
* **calibrate** — benign only. Thresholds are chosen here, not on train, or the
  false-positive budget would be fitted to data the model has memorised.
* **test**     — a realistic mix. Touched exactly once, at the end.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from forensics.common.logging import configure_logging, get_logger  # noqa: E402
from forensics.inference.evaluate import (  # noqa: E402
    calibrate,
    evaluate,
    score_windows,
    unknown_token_baseline,
)
from forensics.inference.sequences import SequenceBuilder, to_records  # noqa: E402
from forensics.inference.train import TrainingConfig, save_bundle, train  # noqa: E402
from forensics.ingestion.generators import TelemetryGenerator  # noqa: E402

logger = get_logger(__name__, component="train-detector")


def generate(count: int, *, seed: int, anomaly_rate: float, hosts: int, users: int):
    generator = TelemetryGenerator(
        host_count=hosts, user_count=users, anomaly_rate=anomaly_rate, seed=seed
    )
    events = []
    while len(events) < count:
        events.extend(generator.next_events())
    return events[:count]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--window-size", type=int, default=16)
    parser.add_argument("--stride", type=int, default=4)
    parser.add_argument("--train-events", type=int, default=60_000)
    parser.add_argument("--calibration-events", type=int, default=15_000)
    parser.add_argument("--test-events", type=int, default=30_000)
    parser.add_argument(
        "--anomaly-rate", type=float, default=0.01,
        help="event-level attack fraction in the TEST set; real base rates are <1%%",
    )
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--out", default="artifacts/logbert")
    parser.add_argument("--report", default=None, help="write metrics JSON here")
    args = parser.parse_args()

    configure_logging(service="train-detector", environment="local", level="INFO")

    started = time.perf_counter()
    train_events = generate(args.train_events, seed=101, anomaly_rate=0.0, hosts=25, users=60)
    calib_events = generate(args.calibration_events, seed=202, anomaly_rate=0.0, hosts=25, users=60)
    test_events = generate(
        args.test_events, seed=303, anomaly_rate=args.anomaly_rate, hosts=20, users=75
    )

    builder = SequenceBuilder(window_size=args.window_size, stride=args.stride)
    train_windows = builder.fit(to_records(train_events))
    calib_windows = builder.transform(to_records(calib_events))
    test_windows = builder.transform(to_records(test_events))

    logger.info(
        "Datasets prepared",
        extra={
            "templates": builder.miner.vocabulary_size,
            "vocabulary": builder.vocabulary.size,
            "train_windows": len(train_windows),
            "calibration_windows": len(calib_windows),
            "test_windows": len(test_windows),
            "test_anomalous_windows": sum(w.is_anomaly for w in test_windows),
            "seconds": round(time.perf_counter() - started, 1),
        },
    )

    result = train(
        train_windows, builder, config=TrainingConfig(epochs=args.epochs, batch_size=256)
    )

    calib_scores = score_windows(result.model, calib_windows)
    test_scores = score_windows(result.model, test_windows)
    threshold = calibrate(calib_scores, target_false_positive_rate=args.target_fpr)

    model_metrics = evaluate(test_windows, test_scores, threshold)
    baseline_metrics = unknown_token_baseline(test_windows)

    print("\n" + "=" * 72)
    print(f"  LogBERT       {model_metrics.summary()}")
    print(f"  UNK baseline  {baseline_metrics.summary()}")
    print("=" * 72)
    print(f"\n  thresholds @ target FPR {args.target_fpr:.1%}:")
    for name, cut in threshold.cuts.items():
        print(f"    {name:<18} >= {cut:.4f}")
    print(f"\n  {'scenario':<28} {'LogBERT':>9} {'UNK-rule':>9}")
    for name, value in model_metrics.per_scenario_recall.items():
        base = baseline_metrics.per_scenario_recall.get(name, 0.0)
        print(f"    {name:<26} {value:>9.3f} {base:>9.3f}")
    print(
        f"\n  confusion: TP={model_metrics.true_positives} FP={model_metrics.false_positives} "
        f"FN={model_metrics.false_negatives} TN={model_metrics.true_negatives}"
    )

    save_bundle(result, args.out, threshold=threshold)

    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(
            json.dumps(
                {
                    # asdict, not __dict__: Metrics is a slots dataclass.
                    "model": dataclasses.asdict(model_metrics),
                    "unknown_token_baseline": dataclasses.asdict(baseline_metrics),
                    "thresholds": threshold.cuts,
                    "target_fpr": args.target_fpr,
                    "templates": builder.miner.vocabulary_size,
                    "vocabulary": builder.vocabulary.size,
                    "history": result.history,
                },
                indent=2,
                default=str,
            )
        )
        logger.info("Wrote report", extra={"path": args.report})

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
