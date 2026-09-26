"""Fixtures for the detector tests.

These need PyTorch, which lives in the Spark venv rather than the core one —
installing a second ~2 GB copy to run a handful of tests is not worth it. Run
with `make test-model`; the core suite skips them cleanly.
"""

from __future__ import annotations

import datetime as dt

import pytest

pytest.importorskip("torch", reason="torch not installed (use `make test-model`)")

from forensics.inference.sequences import SequenceBuilder, to_records  # noqa: E402
from forensics.ingestion.generators import TelemetryGenerator  # noqa: E402

BASE = dt.datetime(2026, 9, 9, 12, 0, tzinfo=dt.UTC)


def _generate(count: int, *, seed: int, anomaly_rate: float, hosts: int = 8):
    generator = TelemetryGenerator(
        host_count=hosts, user_count=20, anomaly_rate=anomaly_rate, seed=seed
    )
    events = []
    while len(events) < count:
        events.extend(generator.next_events())
    return events[:count]


@pytest.fixture(scope="session")
def fitted_builder() -> SequenceBuilder:
    builder = SequenceBuilder(window_size=8, stride=4)
    builder.fit(to_records(_generate(6000, seed=101, anomaly_rate=0.0)))
    return builder


@pytest.fixture(scope="session")
def benign_windows(fitted_builder: SequenceBuilder):
    return fitted_builder.transform(to_records(_generate(4000, seed=202, anomaly_rate=0.0)))


@pytest.fixture(scope="session")
def mixed_windows(fitted_builder: SequenceBuilder):
    return fitted_builder.transform(to_records(_generate(4000, seed=303, anomaly_rate=0.08)))


@pytest.fixture(scope="session")
def trained(fitted_builder: SequenceBuilder):
    """A small model trained on benign data, shared across the module."""
    from forensics.inference.train import TrainingConfig, train

    windows = fitted_builder.transform(
        to_records(_generate(6000, seed=101, anomaly_rate=0.0))
    )
    return train(
        windows,
        fitted_builder,
        config=TrainingConfig(epochs=6, batch_size=128, seed=7),
        device=__import__("torch").device("cpu"),
    )
