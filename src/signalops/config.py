"""SignalOps configuration, read from the environment.

Reuses the pipeline's stdlib env helpers so the conventions (fail fast, typed
casts, empty == unset) are identical across every service. Every external
integration is optional: with nothing but Postgres reachable, the API and
dashboard start and report the rest as unavailable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from forensics.common.config import ConfigError, env_bool, env_float, env_int, env_list, env_str

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Spark query names started by forensics.streaming.job.start_queries.
DEFAULT_STREAM_QUERIES = (
    "normalized-events",
    "dead-letters",
    "host-activity-features",
    "peer-connection-features",
    "evidence-store",
)

#: Topics created by scripts/create-topics.sh.
DEFAULT_TOPICS = (
    "logs.raw",
    "logs.normalized",
    "logs.raw.dlq",
    "features.host_activity",
    "features.peer_connections",
    "alerts.anomalies",
)


def postgres_dsn_from_env() -> str:
    """Same POSTGRES_* variables the migrate and sealer services use."""
    explicit = os.environ.get("SIGNALOPS_POSTGRES_DSN", "").strip()
    if explicit:
        return explicit
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "forensics")
    user = os.environ.get("POSTGRES_USER", "forensics")
    password = os.environ.get("POSTGRES_PASSWORD", "")
    return f"host={host} port={port} dbname={db} user={user} password={password}"


@dataclass(frozen=True)
class Thresholds:
    """Documented, deterministic policy for health and incident derivation.

    See docs/signalops.md ("Incident candidates") — every number here is a
    policy choice, not a measurement, and is overridable by environment.
    """

    stream_stale_seconds: int = 180
    detector_stale_seconds: int = 900
    dlq_ratio_warn: float = 0.05
    dlq_ratio_high: float = 0.25
    dlq_min_records: int = 10
    normalize_backlog_rows: int = 50_000
    normalize_backlog_age_seconds: int = 600
    seal_stale_seconds: int = 300
    verification_stale_seconds: int = 3_600
    anomaly_cluster_high: int = 5

    @classmethod
    def from_env(cls) -> Thresholds:
        return cls(
            stream_stale_seconds=env_int("SIGNALOPS_STREAM_STALE_SECONDS", 180),
            detector_stale_seconds=env_int("SIGNALOPS_DETECTOR_STALE_SECONDS", 900),
            dlq_ratio_warn=env_float("SIGNALOPS_DLQ_RATIO_WARN", 0.05),
            dlq_ratio_high=env_float("SIGNALOPS_DLQ_RATIO_HIGH", 0.25),
            dlq_min_records=env_int("SIGNALOPS_DLQ_MIN_RECORDS", 10),
            normalize_backlog_rows=env_int("SIGNALOPS_NORMALIZE_BACKLOG_ROWS", 50_000),
            normalize_backlog_age_seconds=env_int("SIGNALOPS_NORMALIZE_BACKLOG_AGE_SECONDS", 600),
            seal_stale_seconds=env_int("SIGNALOPS_SEAL_STALE_SECONDS", 300),
            verification_stale_seconds=env_int("SIGNALOPS_VERIFICATION_STALE_SECONDS", 3_600),
            anomaly_cluster_high=env_int("SIGNALOPS_ANOMALY_CLUSTER_HIGH", 5),
        )


@dataclass(frozen=True)
class LLMSettings:
    """Investigation provider. ``provider = "none"`` disables investigations."""

    provider: str = "none"  # anthropic | offline | none
    model: str = "claude-opus-5-5"
    effort: str = "medium"
    max_tokens: int = 16_000
    request_timeout_seconds: float = 60.0
    investigation_timeout_seconds: float = 180.0
    max_tool_calls: int = 12
    max_turns: int = 10
    server_fallbacks: bool = True

    @classmethod
    def from_env(cls) -> LLMSettings:
        provider = env_str("SIGNALOPS_LLM_PROVIDER", "").lower()
        if not provider:
            # Infer from credentials so a key alone is enough to turn it on.
            provider = "anthropic" if os.environ.get("ANTHROPIC_API_KEY") else "none"
        if provider not in {"anthropic", "offline", "none"}:
            raise ConfigError(
                f"SIGNALOPS_LLM_PROVIDER must be anthropic, offline or none, got {provider!r}"
            )
        effort = env_str("SIGNALOPS_LLM_EFFORT", "medium").lower()
        if effort not in {"low", "medium", "high", "xhigh", "max"}:
            raise ConfigError(f"SIGNALOPS_LLM_EFFORT is not a valid effort level: {effort!r}")
        return cls(
            provider=provider,
            model=env_str("SIGNALOPS_LLM_MODEL", "claude-opus-5-5"),
            effort=effort,
            max_tokens=env_int("SIGNALOPS_LLM_MAX_TOKENS", 16_000),
            request_timeout_seconds=env_float("SIGNALOPS_LLM_REQUEST_TIMEOUT_SECONDS", 60.0),
            investigation_timeout_seconds=env_float(
                "SIGNALOPS_INVESTIGATION_TIMEOUT_SECONDS", 180.0
            ),
            max_tool_calls=env_int("SIGNALOPS_MAX_TOOL_CALLS", 12),
            max_turns=env_int("SIGNALOPS_MAX_TURNS", 10),
            server_fallbacks=env_bool("SIGNALOPS_LLM_SERVER_FALLBACKS", True),
        )


@dataclass(frozen=True)
class SlackSettings:
    signing_secret: str = ""
    allowed_user_ids: tuple[str, ...] = ()
    allowed_channel_ids: tuple[str, ...] = ()

    @property
    def enabled(self) -> bool:
        return bool(self.signing_secret)

    @classmethod
    def from_env(cls) -> SlackSettings:
        return cls(
            signing_secret=env_str("SLACK_SIGNING_SECRET", ""),
            allowed_user_ids=tuple(env_list("SLACK_ALLOWED_USER_IDS", [])),
            allowed_channel_ids=tuple(env_list("SLACK_ALLOWED_CHANNEL_IDS", [])),
        )


@dataclass(frozen=True)
class Settings:
    environment: str = "local"
    log_level: str = "INFO"
    postgres_dsn: str = ""
    db_connect_timeout_seconds: int = 3
    db_statement_timeout_ms: int = 5_000
    kafka_bootstrap_servers: str = "localhost:29092"
    kafka_timeout_seconds: float = 3.0
    raw_topic: str = "logs.raw"
    dlq_topic: str = "logs.raw.dlq"
    topics: tuple[str, ...] = DEFAULT_TOPICS
    stream_queries: tuple[str, ...] = DEFAULT_STREAM_QUERIES
    scorer_consumer_group: str = "forensics-scorer"
    runbook_dir: Path = REPO_ROOT / "runbooks"
    api_key: str = ""
    cache_ttl_seconds: float = 5.0
    thresholds: Thresholds = field(default_factory=Thresholds)
    llm: LLMSettings = field(default_factory=LLMSettings)
    slack: SlackSettings = field(default_factory=SlackSettings)

    @classmethod
    def from_env(cls) -> Settings:
        raw_topic = env_str("KAFKA_RAW_LOGS_TOPIC", "logs.raw")
        dlq_topic = env_str("KAFKA_DLQ_TOPIC", "logs.raw.dlq")
        return cls(
            environment=env_str("APP_ENV", "local"),
            log_level=env_str("LOG_LEVEL", "INFO").upper(),
            postgres_dsn=postgres_dsn_from_env(),
            db_connect_timeout_seconds=env_int("SIGNALOPS_DB_CONNECT_TIMEOUT_SECONDS", 3),
            db_statement_timeout_ms=env_int("SIGNALOPS_DB_STATEMENT_TIMEOUT_MS", 5_000),
            kafka_bootstrap_servers=env_str("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092"),
            kafka_timeout_seconds=env_float("SIGNALOPS_KAFKA_TIMEOUT_SECONDS", 3.0),
            raw_topic=raw_topic,
            dlq_topic=dlq_topic,
            topics=tuple(env_list("SIGNALOPS_TOPICS", list(DEFAULT_TOPICS))),
            stream_queries=tuple(
                env_list("SIGNALOPS_STREAM_QUERIES", list(DEFAULT_STREAM_QUERIES))
            ),
            scorer_consumer_group=env_str("SCORER_CONSUMER_GROUP", "forensics-scorer"),
            runbook_dir=Path(env_str("SIGNALOPS_RUNBOOK_DIR", str(REPO_ROOT / "runbooks"))),
            api_key=env_str("SIGNALOPS_API_KEY", ""),
            cache_ttl_seconds=env_float("SIGNALOPS_CACHE_TTL_SECONDS", 5.0),
            thresholds=Thresholds.from_env(),
            llm=LLMSettings.from_env(),
            slack=SlackSettings.from_env(),
        )
