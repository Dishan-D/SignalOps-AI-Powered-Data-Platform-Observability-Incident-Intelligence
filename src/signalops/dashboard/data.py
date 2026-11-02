"""Dashboard data access and display transforms (no Streamlit imports).

The dashboard reads only the operational API, so what it shows is exactly what
the API, Slack and the agent see. Everything that decides *what to display* is
here as plain functions so it can be tested without a browser:

* a metric that is not ``ok`` renders as an em dash plus its state, never as 0;
* staleness is computed from the server's own timestamps;
* a failed or malformed API response becomes an :class:`ApiResult` error, so a
  section degrades to a message instead of crashing the page.
"""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from typing import Any

STATUS_ICON = {
    "healthy": "🟢", "degraded": "🟡", "unhealthy": "🔴", "unavailable": "⚫", "unknown": "⚪",
}
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "unknown": "⚪"}
STATE_LABEL = {"unknown": "no data", "unavailable": "source unavailable", "error": "query failed"}

#: Reference categorical palette, slots 1-3 (validated all-pairs, light and dark).
SERIES_COLORS = ("#2a78d6", "#eb6834", "#1baf7a")


@dataclass(frozen=True)
class ApiResult:
    ok: bool
    data: Any
    error: str | None
    fetched_at: dt.datetime
    status_code: int | None = None


class ApiClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 timeout: float = 15.0, transport: Any = None) -> None:
        import httpx

        self.base_url = (base_url or os.environ.get("SIGNALOPS_API_URL", "http://127.0.0.1:8000")).rstrip("/")
        key = api_key if api_key is not None else os.environ.get("SIGNALOPS_API_KEY", "")
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport,
                                    headers={"x-api-key": key} if key else {})

    def _call(self, method: str, path: str, **kwargs: Any) -> ApiResult:
        import httpx

        now = dt.datetime.now(tz=dt.timezone.utc)
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            return ApiResult(False, None, f"API unreachable at {self.base_url} ({exc.__class__.__name__})", now)
        try:
            body = response.json()
        except ValueError:
            return ApiResult(False, None, f"API returned non-JSON (HTTP {response.status_code})", now,
                             response.status_code)
        if response.status_code >= 400:
            message = error_message(body) or f"HTTP {response.status_code}"
            return ApiResult(False, body, message, now, response.status_code)
        return ApiResult(True, body, None, now, response.status_code)

    def get(self, path: str, **params: Any) -> ApiResult:
        return self._call("GET", path, params={k: v for k, v in params.items() if v is not None})

    def post(self, path: str, payload: dict[str, Any]) -> ApiResult:
        return self._call("POST", path, json=payload)


def error_message(body: Any) -> str | None:
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            return str(err.get("message") or err.get("code") or "error")
        if "detail" in body:
            return str(body["detail"])
    return None


def dig(data: Any, *keys: Any, default: Any = None) -> Any:
    """Nested lookup that tolerates missing keys and wrong types."""
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        elif isinstance(data, list) and isinstance(key, int) and -len(data) <= key < len(data):
            data = data[key]
        else:
            return default
        if data is None:
            return default
    return data


def parse_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def age_seconds(value: Any, now: dt.datetime | None = None) -> float | None:
    moment = parse_time(value)
    if moment is None:
        return None
    return max(0.0, ((now or dt.datetime.now(tz=dt.timezone.utc)) - moment).total_seconds())


def is_stale(value: Any, max_age_seconds: float, now: dt.datetime | None = None) -> bool:
    """Unknown timestamps count as stale: absence of evidence is not freshness."""
    age = age_seconds(value, now)
    return age is None or age > max_age_seconds


def humanize_age(seconds: float | None) -> str:
    if seconds is None:
        return "never"
    if seconds < 90:
        return f"{int(seconds)}s ago"
    if seconds < 5400:
        return f"{int(seconds // 60)}m ago"
    if seconds < 172_800:
        return f"{seconds / 3600:.1f}h ago"
    return f"{seconds / 86400:.1f}d ago"


def format_number(value: float, unit: str | None) -> str:
    if unit == "fraction":
        return f"{value:.1%}"
    if unit == "seconds":
        return f"{value:.1f}s" if value < 120 else humanize_age(value).replace(" ago", "")
    text = f"{int(value):,}" if float(value).is_integer() else f"{value:,.2f}"
    return f"{text} {unit}" if unit and unit not in {"records", "windows"} else text


def metric_display(metric: Any) -> tuple[str, str | None]:
    """(display value, note). Non-ok metrics never display a number."""
    if not isinstance(metric, dict) or "state" not in metric:
        return "—", "malformed metric"
    state = metric.get("state")
    if state != "ok" or metric.get("value") is None:
        return "—", f"{STATE_LABEL.get(str(state), str(state))}: {metric.get('detail') or ''}".strip(": ")
    try:
        return format_number(float(metric["value"]), metric.get("unit")), metric.get("detail")
    except (TypeError, ValueError):
        return "—", "malformed metric value"


def metrics_by_name(payload: Any) -> dict[str, dict[str, Any]]:
    return {m["name"]: m for m in dig(payload, "metrics", default=[])
            if isinstance(m, dict) and "name" in m}


def series_by_name(payload: Any) -> dict[str, dict[str, Any]]:
    return {s["name"]: s for s in dig(payload, "series", default=[])
            if isinstance(s, dict) and "name" in s}


def series_points(series: Any) -> tuple[list[dt.datetime], list[float]] | None:
    """Points for plotting, or None when the series is not a real measurement."""
    if not isinstance(series, dict) or series.get("state") != "ok":
        return None
    xs, ys = [], []
    for point in series.get("points") or []:
        t = parse_time(dig(point, "bucket"))
        v = dig(point, "value")
        if t is None or not isinstance(v, (int, float)):
            continue
        xs.append(t)
        ys.append(float(v))
    return xs, ys


def series_note(series: Any) -> str:
    if not isinstance(series, dict):
        return "series missing from response"
    return f"{STATE_LABEL.get(series.get('state', ''), series.get('state'))}: {series.get('detail') or ''}"


def status_label(status: Any) -> str:
    text = str(status or "unknown")
    return f"{STATUS_ICON.get(text, '⚪')} {text}"


def incident_options(payload: Any) -> list[tuple[str, str]]:
    """(incident_id, label) pairs for a selector."""
    out = []
    for c in dig(payload, "candidates", default=[]):
        if isinstance(c, dict) and c.get("incident_id"):
            sev = str(c.get("severity", "unknown"))
            out.append((c["incident_id"], f"{SEVERITY_ICON.get(sev, '⚪')} [{sev}] {c.get('title', c['incident_id'])}"))
    return out


def component_rows(health: Any) -> list[dict[str, Any]]:
    rows = []
    for c in dig(health, "components", default=[]):
        if not isinstance(c, dict):
            continue
        rows.append({"component": c.get("name", "?"), "status": status_label(c.get("status")),
                     "detail": c.get("detail", ""), "latency_ms": c.get("latency_ms")})
    return rows
