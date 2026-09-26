"""Environment-driven configuration.

Design rules for this layer:

* **Twelve-factor.** Every knob is an environment variable. Nothing is read from
  a config file at runtime, so the same image runs in Compose, CI and k8s.
* **Fail fast.** Malformed or missing-but-required values raise
  :class:`ConfigError` at startup rather than surfacing as a confusing
  ``TypeError`` deep inside a hot loop an hour later.
* **Stdlib only.** No pydantic/dynaconf here. Configuration is the one module
  every other module imports, and keeping it dependency-free means the schema,
  the generators and the tests can be exercised without installing a native
  Kafka client.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")

# Sentinel distinguishing "no default supplied" (i.e. required) from a
# legitimate default of ``None``.
_UNSET: object = object()


class ConfigError(RuntimeError):
    """Raised when the process environment cannot produce a valid config."""


def _get(
    name: str,
    cast: Callable[[str], T],
    default: object = _UNSET,
    *,
    kind: str,
) -> T:
    """Read ``name`` from the environment and coerce it with ``cast``."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        if default is _UNSET:
            raise ConfigError(f"Required environment variable {name!r} is not set")
        return default  # type: ignore[return-value]
    try:
        return cast(raw.strip())
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            f"Environment variable {name}={raw!r} is not a valid {kind}"
        ) from exc


def env_str(name: str, default: object = _UNSET) -> str:
    return _get(name, str, default, kind="string")


def env_int(name: str, default: object = _UNSET) -> int:
    return _get(name, int, default, kind="integer")


def env_float(name: str, default: object = _UNSET) -> float:
    return _get(name, float, default, kind="float")


def env_bool(name: str, default: object = _UNSET) -> bool:
    def _cast(raw: str) -> bool:
        lowered = raw.lower()
        if lowered in {"1", "true", "yes", "y", "on"}:
            return True
        if lowered in {"0", "false", "no", "n", "off"}:
            return False
        raise ValueError(raw)

    return _get(name, _cast, default, kind="boolean")


def env_list(name: str, default: object = _UNSET) -> list[str]:
    """Parse a comma-separated list, dropping empty members."""
    return _get(
        name,
        lambda raw: [item.strip() for item in raw.split(",") if item.strip()],
        default,
        kind="comma-separated list",
    )


@dataclass(frozen=True, slots=True)
class KafkaSettings:
    """Connection + delivery-guarantee settings for the Kafka client."""

    bootstrap_servers: str
    client_id: str
    raw_logs_topic: str
    dlq_topic: str
    # Durability: 'all' waits for every in-sync replica. Combined with
    # idempotence this gives exactly-once *produce* semantics per partition.
    acks: str = "all"
    enable_idempotence: bool = True
    compression_type: str = "zstd"
    # Bound how long a produce may block before we consider it failed. The
    # client retries internally within this budget.
    message_timeout_ms: int = 30_000
    request_timeout_ms: int = 15_000
    # linger trades a little latency for far better batching/throughput.
    linger_ms: int = 25
    batch_size: int = 65_536
    queue_buffering_max_messages: int = 200_000
    security_protocol: str = "PLAINTEXT"

    @classmethod
    def from_env(cls) -> KafkaSettings:
        return cls(
            bootstrap_servers=env_str("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092"),
            client_id=env_str("KAFKA_CLIENT_ID", "forensics-producer"),
            raw_logs_topic=env_str("KAFKA_RAW_LOGS_TOPIC", "logs.raw"),
            dlq_topic=env_str("KAFKA_DLQ_TOPIC", "logs.raw.dlq"),
            acks=env_str("KAFKA_ACKS", "all"),
            enable_idempotence=env_bool("KAFKA_ENABLE_IDEMPOTENCE", True),
            compression_type=env_str("KAFKA_COMPRESSION_TYPE", "zstd"),
            message_timeout_ms=env_int("KAFKA_MESSAGE_TIMEOUT_MS", 30_000),
            request_timeout_ms=env_int("KAFKA_REQUEST_TIMEOUT_MS", 15_000),
            linger_ms=env_int("KAFKA_LINGER_MS", 25),
            batch_size=env_int("KAFKA_BATCH_SIZE", 65_536),
            queue_buffering_max_messages=env_int("KAFKA_QUEUE_MAX_MESSAGES", 200_000),
            security_protocol=env_str("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT"),
        )


@dataclass(frozen=True, slots=True)
class ProducerSettings:
    """Behaviour of the synthetic log producer itself."""

    events_per_second: float
    max_events: int  # 0 == run until signalled
    anomaly_rate: float  # probability that a tick starts an attack scenario
    host_count: int
    user_count: int
    seed: int | None
    dry_run: bool  # emit to stdout instead of Kafka
    dlq_spool_path: str
    stats_interval_seconds: float

    @classmethod
    def from_env(cls) -> ProducerSettings:
        seed_raw = os.environ.get("PRODUCER_SEED", "").strip()
        anomaly_rate = env_float("PRODUCER_ANOMALY_RATE", 0.03)
        if not 0.0 <= anomaly_rate <= 1.0:
            raise ConfigError(
                f"PRODUCER_ANOMALY_RATE must be within [0.0, 1.0], got {anomaly_rate}"
            )
        events_per_second = env_float("PRODUCER_EVENTS_PER_SECOND", 25.0)
        if events_per_second <= 0:
            raise ConfigError("PRODUCER_EVENTS_PER_SECOND must be greater than 0")
        return cls(
            events_per_second=events_per_second,
            max_events=env_int("PRODUCER_MAX_EVENTS", 0),
            anomaly_rate=anomaly_rate,
            host_count=env_int("PRODUCER_HOST_COUNT", 12),
            user_count=env_int("PRODUCER_USER_COUNT", 25),
            seed=int(seed_raw) if seed_raw else None,
            dry_run=env_bool("PRODUCER_DRY_RUN", False),
            dlq_spool_path=env_str("PRODUCER_DLQ_SPOOL_PATH", "/var/spool/forensics/dlq.jsonl"),
            stats_interval_seconds=env_float("PRODUCER_STATS_INTERVAL_SECONDS", 10.0),
        )


@dataclass(frozen=True, slots=True)
class SparkSettings:
    """Spark Structured Streaming job settings."""

    app_name: str
    master: str
    checkpoint_location: str
    # Offset to start from on a *fresh* checkpoint. "earliest" replays the
    # retained topic, "latest" skips history. Ignored once a checkpoint exists —
    # a frequent source of "why is my change not taking effect".
    starting_offsets: str
    max_offsets_per_trigger: int
    trigger_interval: str
    shuffle_partitions: int
    # How late an event may arrive and still be counted in its window. Bounds
    # state-store growth; anything later is dropped.
    watermark_delay: str
    window_duration: str
    window_slide: str
    # Optional JDBC sink for normalised events.
    postgres_enabled: bool
    postgres_url: str
    postgres_user: str
    postgres_password: str
    postgres_batch_size: int

    @classmethod
    def from_env(cls) -> SparkSettings:
        return cls(
            app_name=env_str("SPARK_APP_NAME", "forensics-normalizer"),
            master=env_str("SPARK_MASTER_URL", "local[*]"),
            checkpoint_location=env_str(
                "SPARK_CHECKPOINT_LOCATION", "/var/lib/spark/checkpoints"
            ),
            starting_offsets=env_str("SPARK_STARTING_OFFSETS", "earliest"),
            max_offsets_per_trigger=env_int("SPARK_MAX_OFFSETS_PER_TRIGGER", 50_000),
            trigger_interval=env_str("SPARK_TRIGGER_INTERVAL", "10 seconds"),
            shuffle_partitions=env_int("SPARK_SHUFFLE_PARTITIONS", 8),
            watermark_delay=env_str("SPARK_WATERMARK_DELAY", "2 minutes"),
            window_duration=env_str("SPARK_WINDOW_DURATION", "1 minute"),
            window_slide=env_str("SPARK_WINDOW_SLIDE", "30 seconds"),
            postgres_enabled=env_bool("SPARK_POSTGRES_ENABLED", False),
            postgres_url=env_str(
                "SPARK_POSTGRES_URL", "jdbc:postgresql://postgres:5432/forensics"
            ),
            postgres_user=env_str("SPARK_POSTGRES_USER", "forensics"),
            postgres_password=env_str("SPARK_POSTGRES_PASSWORD", ""),
            postgres_batch_size=env_int("SPARK_POSTGRES_BATCH_SIZE", 1_000),
        )


@dataclass(frozen=True, slots=True)
class AppSettings:
    """Settings common to every service entrypoint.

    Tier-specific configuration (:class:`ProducerSettings`,
    :class:`SparkSettings`) is composed by the service that needs it rather than
    being materialised here, so a Spark job never has to satisfy producer
    validation it does not use.
    """

    service_name: str
    environment: str
    log_level: str
    kafka: KafkaSettings

    @classmethod
    def from_env(cls, service_name: str) -> AppSettings:
        return cls(
            service_name=env_str("SERVICE_NAME", service_name),
            environment=env_str("APP_ENV", "local"),
            log_level=env_str("LOG_LEVEL", "INFO").upper(),
            kafka=KafkaSettings.from_env(),
        )
