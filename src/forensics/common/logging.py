"""Structured JSON logging.

Every service emits one JSON object per line on stdout. That is the contract a
log shipper (Fluent Bit, Vector, CloudWatch Agent) expects, and it means our own
operational logs are queryable with the same tooling as the security telemetry
we ingest.

Two details that matter in production and are easy to get wrong:

* ``logging`` is not the place for ad-hoc string interpolation. Callers pass
  structured fields via ``extra={...}``; those land as top-level JSON keys so
  they can be indexed instead of regex-scraped.
* A correlation id is carried in a :mod:`contextvars` variable, so it survives
  across function boundaries (and asyncio tasks) without being threaded through
  every signature.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import sys
from collections.abc import Iterator, Mapping, MutableMapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, TextIO

# Correlation id propagated into every log record emitted downstream of a bind.
_correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)

# Attributes the stdlib puts on every LogRecord. Anything *not* in this set was
# supplied by the caller via ``extra=`` and therefore belongs in the payload.
_RESERVED_RECORD_ATTRS = frozenset(
    {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "message", "module",
        "msecs", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "taskName", "thread", "threadName",
    }
)


class JsonFormatter(logging.Formatter):
    """Render a :class:`logging.LogRecord` as a single-line JSON object."""

    def __init__(self, *, service: str, environment: str) -> None:
        super().__init__()
        self._service = service
        self._environment = environment
        self._host = os.environ.get("HOSTNAME", "unknown")

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": dt.datetime.fromtimestamp(
                record.created, tz=dt.timezone.utc
            ).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self._service,
            "environment": self._environment,
            "host": self._host,
        }

        correlation_id = _correlation_id.get()
        if correlation_id:
            payload["correlation_id"] = correlation_id

        # Promote caller-supplied ``extra`` fields to top-level keys.
        for key, value in record.__dict__.items():
            if key not in _RESERVED_RECORD_ATTRS and not key.startswith("_"):
                payload[key] = value

        if record.exc_info:
            payload["error"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "stack_trace": self.formatException(record.exc_info),
            }

        # ``default=str`` keeps the logger from ever raising on an exotic value;
        # a log call must never be the thing that takes the service down.
        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(
    *,
    service: str,
    environment: str,
    level: str = "INFO",
    stream: TextIO | None = None,
) -> None:
    """Install the JSON formatter as the sole root handler (idempotent).

    ``stream`` defaults to stdout, which is what a container log collector
    expects. Services that write *data* to stdout (the producer's dry-run mode)
    pass ``sys.stderr`` instead, so the two streams never interleave and
    ``... | jq`` stays usable.
    """
    handler = logging.StreamHandler(stream=stream or sys.stdout)
    handler.setFormatter(JsonFormatter(service=service, environment=environment))

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # These libraries are chatty at INFO and drown out our own signal.
    logging.getLogger("kafka").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def set_correlation_id(correlation_id: str | None) -> None:
    _correlation_id.set(correlation_id)


@contextmanager
def correlation_scope(correlation_id: str) -> Iterator[None]:
    """Bind ``correlation_id`` to every log record emitted inside the block."""
    token = _correlation_id.set(correlation_id)
    try:
        yield
    finally:
        _correlation_id.reset(token)


def get_logger(name: str, **bound: Any) -> logging.LoggerAdapter:
    """Return a logger whose every record carries the ``bound`` fields."""
    return _BoundLogger(logging.getLogger(name), bound)


class _BoundLogger(logging.LoggerAdapter):
    """LoggerAdapter that merges bound context into ``extra`` (call wins)."""

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> tuple[Any, MutableMapping[str, Any]]:
        extra: dict[str, Any] = dict(self.extra or {})
        caller_extra = kwargs.get("extra")
        if isinstance(caller_extra, Mapping):
            extra.update(caller_extra)
        kwargs["extra"] = extra
        return msg, kwargs
