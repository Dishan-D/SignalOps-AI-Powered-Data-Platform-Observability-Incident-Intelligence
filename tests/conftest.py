"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from forensics.ingestion.generators import TelemetryGenerator


@pytest.fixture
def generator() -> TelemetryGenerator:
    """Deterministic generator so assertions are reproducible."""
    return TelemetryGenerator(host_count=6, user_count=10, anomaly_rate=0.05, seed=1234)
