"""Configuration layer: defaults, coercion, and fail-fast validation."""

from __future__ import annotations

import os

import pytest

from forensics.common.config import (
    ConfigError,
    KafkaSettings,
    ProducerSettings,
    env_bool,
    env_int,
    env_list,
)


def test_required_variable_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOME_REQUIRED", raising=False)
    with pytest.raises(ConfigError, match="SOME_REQUIRED"):
        env_int("SOME_REQUIRED")


def test_blank_value_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # An unset variable in Compose often arrives as "" rather than absent.
    monkeypatch.setenv("MAYBE_BLANK", "   ")
    assert env_int("MAYBE_BLANK", 42) == 42


def test_invalid_value_raises_with_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOT_A_NUMBER", "twelve")
    with pytest.raises(ConfigError, match="integer"):
        env_int("NOT_A_NUMBER")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", True), ("TRUE", True), ("1", True), ("yes", True), ("on", True),
     ("false", False), ("0", False), ("no", False), ("off", False)],
)
def test_bool_parsing(monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool) -> None:
    monkeypatch.setenv("FLAG", raw)
    assert env_bool("FLAG") is expected


def test_bool_rejects_garbage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLAG", "maybe")
    with pytest.raises(ConfigError, match="boolean"):
        env_bool("FLAG")


def test_list_parsing_drops_empty_members(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROKERS", "a:9092, b:9092 ,, c:9092")
    assert env_list("BROKERS") == ["a:9092", "b:9092", "c:9092"]


def test_anomaly_rate_out_of_range_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRODUCER_ANOMALY_RATE", "1.5")
    with pytest.raises(ConfigError, match="within"):
        ProducerSettings.from_env()


def test_non_positive_rate_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRODUCER_EVENTS_PER_SECOND", "0")
    with pytest.raises(ConfigError, match="greater than 0"):
        ProducerSettings.from_env()


def test_kafka_defaults_are_production_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in [k for k in os.environ if k.startswith("KAFKA_")]:
        monkeypatch.delenv(key, raising=False)
    settings = KafkaSettings.from_env()
    # Durability must not silently degrade if the env is empty.
    assert settings.acks == "all"
    assert settings.enable_idempotence is True
