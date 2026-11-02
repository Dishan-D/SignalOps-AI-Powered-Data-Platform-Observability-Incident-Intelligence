"""Dashboard transforms: missing != zero, staleness, failed and malformed responses."""

from __future__ import annotations

import datetime as dt

import httpx
import pytest

from signalops.dashboard.data import (
    ApiClient,
    age_seconds,
    component_rows,
    dig,
    incident_options,
    is_stale,
    metric_display,
    metrics_by_name,
    series_points,
    status_label,
)

NOW = dt.datetime(2026, 10, 23, 12, 0, tzinfo=dt.timezone.utc)


@pytest.mark.parametrize("state", ["unknown", "unavailable", "error"])
def test_missing_metric_never_renders_as_zero(state: str) -> None:
    value, note = metric_display({"name": "x", "state": state, "value": None, "detail": "broker down"})
    assert value == "—" and "broker down" in note


def test_real_zero_renders_as_zero() -> None:
    assert metric_display({"name": "x", "state": "ok", "value": 0.0, "unit": "records"})[0] == "0"


@pytest.mark.parametrize(("metric", "expected"), [
    ({"state": "ok", "value": 1234.0, "unit": "records"}, "1,234"),
    ({"state": "ok", "value": 0.2, "unit": "fraction"}, "20.0%"),
    ({"state": "ok", "value": 6.25, "unit": "seconds"}, "6.2s"),
    ({"state": "ok", "value": 150.5, "unit": "rows/s"}, "150.50 rows/s"),
])
def test_metric_formatting(metric: dict, expected: str) -> None:
    assert metric_display(metric)[0] == expected


@pytest.mark.parametrize("bad", [None, "x", 3, {}, {"state": "ok", "value": "NaNish"}])
def test_malformed_metrics_do_not_crash(bad: object) -> None:
    assert metric_display(bad)[0] == "—"


def test_staleness() -> None:
    fresh = (NOW - dt.timedelta(seconds=10)).isoformat()
    old = (NOW - dt.timedelta(minutes=10)).isoformat()
    assert not is_stale(fresh, 60, NOW)
    assert is_stale(old, 60, NOW)
    assert is_stale(None, 60, NOW) and is_stale("not a date", 60, NOW)
    assert age_seconds("2026-10-23T11:59:00Z", NOW) == 60


def test_series_points_only_for_ok_series() -> None:
    ok = {"state": "ok", "points": [{"bucket": "2026-10-23T11:00:00+00:00", "value": 5},
                                    {"bucket": "garbage", "value": 1}, {"bucket": None}]}
    xs, ys = series_points(ok)
    assert ys == [5.0] and len(xs) == 1
    assert series_points({"state": "unavailable", "points": []}) is None
    assert series_points(None) is None


def test_unexpected_structures_are_tolerated() -> None:
    assert metrics_by_name({"metrics": "nope"}) == {}
    assert metrics_by_name(None) == {}
    assert component_rows({"components": [None, {"name": "kafka", "status": "degraded"}]})[0]["component"] == "kafka"
    assert incident_options({"candidates": [{"incident_id": "dlq_spike:x", "severity": "high"}, {}]})[0][0] == "dlq_spike:x"
    assert dig({"a": [1, {"b": 2}]}, "a", 1, "b") == 2 and dig({"a": 1}, "a", "b", default="d") == "d"
    assert status_label("weird").endswith("weird")


def _client(handler) -> ApiClient:
    return ApiClient(base_url="http://api.test", api_key="k", transport=httpx.MockTransport(handler))


def test_api_client_success_and_auth_header() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["key"] = request.headers.get("x-api-key")
        return httpx.Response(200, json={"status": "healthy"})

    result = _client(handler).get("/api/ops/health")
    assert result.ok and result.data["status"] == "healthy" and seen["key"] == "k"


def test_api_client_error_envelope() -> None:
    result = _client(lambda _r: httpx.Response(503, json={"error": {"code": "dependency_unavailable",
                                                                   "message": "cannot connect"}})).get("/x")
    assert not result.ok and result.error == "cannot connect" and result.status_code == 503


def test_api_client_non_json_and_unreachable() -> None:
    assert "non-JSON" in _client(lambda _r: httpx.Response(502, text="<html>")).get("/x").error

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    result = _client(boom).get("/x")
    assert not result.ok and "unreachable" in result.error
