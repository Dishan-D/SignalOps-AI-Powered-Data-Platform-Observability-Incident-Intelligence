"""Canonical wire schema for a raw telemetry event.

The field names follow the **Elastic Common Schema (ECS)** rather than something
bespoke. Two reasons:

1. ECS is what real SIEM/EDR sources emit, so a future Filebeat/Auditbeat feed
   can be pointed at ``logs.raw`` with no translation layer.
2. It gives the Spark normalisation job in Phase 2 a stable contract to code
   against, and gives the Postgres model in Phase 3 an obvious 3NF decomposition
   (host / user / process / network are already separate nested objects).

``message`` carries the original unstructured log line. That is deliberate: the
LogBERT-style parser in Phase 3 consumes the *raw text*, while the structured
fields exist for correlation, joins and evidence presentation.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = "1.0.0"


class EventCategory(StrEnum):
    """ECS ``event.category`` values this pipeline understands."""

    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"


class EventOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class HostFields:
    name: str
    ip: str
    os_family: str = "linux"


@dataclass(slots=True)
class UserFields:
    name: str
    id: int
    domain: str = "corp.local"


@dataclass(slots=True)
class ProcessFields:
    pid: int
    name: str
    executable: str
    command_line: str
    parent_name: str | None = None
    parent_pid: int | None = None


@dataclass(slots=True)
class NetworkFields:
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    transport: str
    bytes_sent: int
    bytes_received: int
    direction: str  # inbound | outbound | internal


@dataclass(slots=True)
class LogEvent:
    """One telemetry record as published to the ``logs.raw`` topic."""

    event_id: str
    timestamp: str  # RFC 3339, always UTC
    category: EventCategory
    action: str
    outcome: EventOutcome
    severity: int  # syslog-style 0 (emerg) .. 7 (debug)
    message: str
    host: HostFields
    dataset: str  # e.g. "linux.auth", "linux.audit", "network.flow"
    user: UserFields | None = None
    process: ProcessFields | None = None
    network: NetworkFields | None = None
    labels: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    # -- construction helpers -------------------------------------------------

    @staticmethod
    def new_id() -> str:
        # uuid4 keeps ids unguessable; the tamper-evident ledger in Phase 4
        # chains on content hashes, not on id ordering.
        return str(uuid.uuid4())

    @staticmethod
    def format_timestamp(moment: dt.datetime) -> str:
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=dt.timezone.utc)
        return moment.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds")

    # -- serialisation --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Nested dict with ``None`` branches pruned to keep payloads compact."""
        raw = asdict(self)
        return {key: value for key, value in raw.items() if value is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), default=str)

    def partition_key(self) -> str:
        """Kafka key.

        Keying by host guarantees all events for a machine land on the same
        partition and therefore arrive in order. Phase 2's session/window
        analytics (failed-login bursts, beaconing intervals) are per-host
        stateful aggregations, so this turns an expensive shuffle into a
        partition-local operation.
        """
        return self.host.name
