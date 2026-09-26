"""The JSON log contract a shipper parses."""

from __future__ import annotations

import io
import json
import logging

from forensics.common.logging import (
    configure_logging,
    correlation_scope,
    get_logger,
)


def _capture(fn) -> list[dict]:
    stream = io.StringIO()
    configure_logging(service="svc", environment="test", level="DEBUG", stream=stream)
    fn(get_logger("t", component="unit"))
    logging.getLogger().handlers[0].flush()
    return [json.loads(line) for line in stream.getvalue().strip().splitlines()]


def test_record_is_single_line_json_with_required_fields() -> None:
    [record] = _capture(lambda log: log.info("hello"))
    assert record["message"] == "hello"
    assert record["level"] == "INFO"
    assert record["service"] == "svc"
    assert record["timestamp"].endswith("+00:00")


def test_extra_fields_are_promoted_to_top_level() -> None:
    [record] = _capture(lambda log: log.info("counted", extra={"events": 7}))
    assert record["events"] == 7
    assert record["component"] == "unit"  # bound at logger construction


def test_exceptions_carry_structured_error_details() -> None:
    def emit(log):
        try:
            raise ValueError("boom")
        except ValueError:
            log.error("failed", exc_info=True)

    [record] = _capture(emit)
    assert record["error"]["type"] == "ValueError"
    assert record["error"]["message"] == "boom"
    assert "ValueError: boom" in record["error"]["stack_trace"]


def test_correlation_id_is_bound_within_scope() -> None:
    def emit(log):
        with correlation_scope("corr-1"):
            log.info("inside")
        log.info("outside")

    inside, outside = _capture(emit)
    assert inside["correlation_id"] == "corr-1"
    assert "correlation_id" not in outside


def test_unserialisable_values_never_raise() -> None:
    [record] = _capture(lambda log: log.info("obj", extra={"thing": object()}))
    assert "object object" in record["thing"]
