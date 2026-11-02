"""The agent's tool set: a fixed, read-only registry over the operational services.

Properties every tool has, enforced here rather than trusted to the model:

* **Closed set.** Only names in the registry execute. An unknown name (for
  example one suggested by text inside a log line) returns an error result and
  does nothing.
* **Validated input.** Arguments are parsed by a Pydantic model with bounds;
  invalid arguments return an error result.
* **Bounded output.** Results are compacted (list and string caps) before they
  reach the model.
* **Read-only.** Every handler calls a service method that only reads; the
  database session itself is read-only (see sources/postgres.py). There is no
  SQL, shell, file or network tool.
* **Explicit failure.** A data-source failure is returned as an error result
  with the reason — never as an empty or zero result.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from signalops.models import Metric, ValueState
from signalops.retrieval.runbooks import RunbookIndex
from signalops.services import OpsServices
from signalops.services.detections import NotFoundError, validate_host_name
from signalops.sources.errors import DataSourceError

MAX_LIST_ITEMS = 15
MAX_STRING_CHARS = 400
MAX_RESULT_CHARS = 9_000


class ToolError(Exception):
    """A tool ran and could not produce a result (reported to the model)."""


# --------------------------------------------------------------------------- #
# Inputs                                                                       #
# --------------------------------------------------------------------------- #

class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoInput(_Input):
    pass


class WindowInput(_Input):
    window_minutes: int = Field(default=60, ge=5, le=1440)


class DlqInput(_Input):
    window_minutes: int = Field(default=60, ge=5, le=1440)
    sample_per_partition: int = Field(default=50, ge=1, le=200)


class DetectionInput(_Input):
    detection_id: int | None = Field(default=None, ge=1)
    host_name: str | None = Field(default=None, max_length=253)
    window_minutes: int = Field(default=60, ge=5, le=1440)


class TimelineInput(_Input):
    host_name: str = Field(max_length=253)
    window_minutes: int = Field(default=60, ge=5, le=1440)
    limit: int = Field(default=50, ge=1, le=200)


class RunbookInput(_Input):
    query: str = Field(min_length=1, max_length=300)
    limit: int = Field(default=3, ge=1, le=5)


# --------------------------------------------------------------------------- #
# Output compaction                                                            #
# --------------------------------------------------------------------------- #

def compact(value: Any, *, max_items: int = MAX_LIST_ITEMS, max_chars: int = MAX_STRING_CHARS) -> Any:
    if isinstance(value, dict):
        return {k: compact(v, max_items=max_items, max_chars=max_chars) for k, v in value.items()}
    if isinstance(value, list):
        items = [compact(v, max_items=max_items, max_chars=max_chars) for v in value[:max_items]]
        if len(value) > max_items:
            items.append(f"... {len(value) - max_items} more omitted")
        return items
    if isinstance(value, str) and len(value) > max_chars:
        return value[:max_chars] + "…"
    return value


def bounded_json(value: Any) -> str:
    """Serialise, shrinking list/string caps until the result fits."""
    for items, chars in ((MAX_LIST_ITEMS, MAX_STRING_CHARS), (8, 250), (4, 150), (2, 100)):
        text = json.dumps(compact(value, max_items=items, max_chars=chars), default=str,
                          separators=(",", ":"))
        if len(text) <= MAX_RESULT_CHARS:
            return text
    return text[:MAX_RESULT_CHARS]


def _metric_line(m: Metric) -> str:
    if m.state is ValueState.ok:
        value = f"{m.value:g}" if m.value is not None else "?"
        return f"{m.name}={value}{' ' + m.unit if m.unit else ''}"
    return f"{m.name}={m.state.value} ({m.detail})"


# --------------------------------------------------------------------------- #
# Registry                                                                     #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_model: type[_Input]
    handler: Callable[[Any], tuple[Any, str]]  # -> (data, one-line summary)

    def definition(self) -> dict[str, Any]:
        """Tool definition for strict tool use.

        Strict mode accepts a JSON Schema subset, so numeric bounds and defaults
        are stripped from the published schema and enforced server-side by the
        Pydantic input model instead.
        """
        def clean(node: dict[str, Any]) -> dict[str, Any]:
            out = {k: v for k, v in node.items() if k in {"type", "description", "enum"}}
            if "anyOf" in node:
                out["anyOf"] = [clean(n) for n in node["anyOf"]]
            return out

        schema = self.input_model.model_json_schema()
        props = {key: clean(prop) for key, prop in schema.get("properties", {}).items()}
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": props,
                "required": list(props),
            },
        }


@dataclass(frozen=True)
class ToolOutcome:
    ok: bool
    content: str
    summary: str
    error: str | None = None


class ToolRegistry:
    def __init__(self, services: OpsServices, runbooks: RunbookIndex) -> None:
        self._services = services
        self._runbooks = runbooks
        #: (source, section) pairs returned by search_runbooks during this run.
        self.retrieved_sections: set[tuple[str, str]] = set()
        self._specs = {s.name: s for s in self._build()}

    @property
    def names(self) -> list[str]:
        return list(self._specs)

    def definitions(self) -> list[dict[str, Any]]:
        return [s.definition() for s in self._specs.values()]

    def execute(self, name: str, arguments: Any) -> ToolOutcome:
        spec = self._specs.get(name)
        if spec is None:
            return ToolOutcome(False, json.dumps({"error": f"unknown tool {name!r}; "
                                                  f"available: {', '.join(self.names)}"}),
                               "rejected: unknown tool", error="unknown tool")
        if not isinstance(arguments, dict):
            return ToolOutcome(False, json.dumps({"error": "arguments must be a JSON object"}),
                               "rejected: invalid arguments", error="invalid arguments")
        # Strict tool schemas mark every field required; null means "use the default".
        cleaned = {k: v for k, v in arguments.items() if v is not None}
        try:
            parsed = spec.input_model.model_validate(cleaned)
        except ValidationError as exc:
            detail = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:5])
            return ToolOutcome(False, json.dumps({"error": f"invalid arguments: {detail}"}),
                               "rejected: invalid arguments", error=f"invalid arguments: {detail}")
        try:
            data, summary = spec.handler(parsed)
        except DataSourceError as exc:
            reason = f"{exc.source} {'unavailable' if exc.unavailable else 'query failed'}: {exc.message}"
            return ToolOutcome(False, json.dumps({"error": reason}), f"failed: {reason}", error=reason)
        except (ToolError, NotFoundError, ValueError) as exc:
            return ToolOutcome(False, json.dumps({"error": str(exc)}), f"failed: {exc}", error=str(exc))
        return ToolOutcome(True, bounded_json(data), summary)

    # -- handlers --------------------------------------------------------------

    def _build(self) -> list[ToolSpec]:
        s = self._services
        return [
            ToolSpec("get_pipeline_health",
                     "Deterministic health of postgres, kafka, spark, detector and ledger, with reasons.",
                     NoInput, self._health),
            ToolSpec("get_pipeline_metrics",
                     "Windowed pipeline metrics (Kafka input, Spark processing and lag, Postgres landing, "
                     "latency percentiles, detections). Each metric states its source and state.",
                     WindowInput, self._metrics),
            ToolSpec("get_recent_failures",
                     "Recent failures: terminated Spark queries with exceptions, normalisation errors, "
                     "and failed ledger verifications.",
                     WindowInput, self._failures),
            ToolSpec("get_dlq_summary",
                     "Dead-letter queue volume, ratio to raw input, sampled validation error reasons and "
                     "sanitised payload previews.",
                     DlqInput, lambda a: self._dlq(a, s)),
            ToolSpec("get_detection_details",
                     "Anomaly detections. With detection_id: one detection with signals, thresholds and "
                     "covered events. Otherwise: recent flagged detections (optionally for host_name).",
                     DetectionInput, self._detections),
            ToolSpec("get_host_timeline",
                     "Normalised events and detections for one host over a time window.",
                     TimelineInput, self._timeline),
            ToolSpec("get_ledger_status",
                     "Evidence ledger sealing state and the latest out-of-database verification result.",
                     NoInput, self._ledger),
            ToolSpec("search_runbooks",
                     "Search the operational runbooks; returns source file, section title and excerpt.",
                     RunbookInput, self._search),
        ]

    def _health(self, _: NoInput) -> tuple[Any, str]:
        health = self._services.cached_health()
        summary = f"overall {health.status.value}: {health.summary}"
        return health.model_dump(mode="json"), summary

    def _metrics(self, args: WindowInput) -> tuple[Any, str]:
        metrics = self._services.cached_metrics(args.window_minutes)
        data = metrics.model_dump(mode="json")
        # Series are for charts; the agent gets the last few points of each.
        for series in data["series"]:
            series["points"] = series["points"][-6:]
        lines = [_metric_line(m) for m in metrics.metrics if m.name.startswith(("spark.", "kafka."))]
        return data, "; ".join(lines[:6]) or "no metrics"

    def _failures(self, args: WindowInput) -> tuple[Any, str]:
        out: dict[str, Any] = {"window_minutes": args.window_minutes}
        errors = []
        try:
            out["terminated_queries"] = [
                q.model_dump(mode="json") for q in self._services.metrics.stream_queries()
                if q.status == "terminated"]
        except DataSourceError as exc:
            errors.append(f"stream queries: {exc.message}")
        dlq = self._services.cached_dlq(args.window_minutes, 20)
        out["normalize_failures_in_window"] = dlq.normalize_failures_in_window.model_dump(mode="json")
        out["recent_normalize_failures"] = [f.model_dump(mode="json") for f in dlq.recent_normalize_failures]
        ledger = self._services.cached_ledger()
        out["failed_ledger_verifications"] = [v.model_dump(mode="json") for v in ledger.recent_failures]
        if errors:
            out["errors"] = errors
        summary = (f"{len(out.get('terminated_queries', []))} terminated queries, "
                   f"{_metric_line(dlq.normalize_failures_in_window)}, "
                   f"{len(ledger.recent_failures)} failed verifications")
        return out, summary

    def _dlq(self, args: DlqInput, s: OpsServices) -> tuple[Any, str]:
        dlq = s.cached_dlq(args.window_minutes, args.sample_per_partition)
        data = dlq.model_dump(mode="json")
        data["samples"] = data["samples"][:8]
        reasons = ", ".join(f"{k}={v}" for k, v in list(dlq.sample_error_counts.items())[:4])
        summary = (f"{_metric_line(dlq.records_in_window)}; {_metric_line(dlq.dlq_ratio)}"
                   + (f"; sampled reasons: {reasons}" if reasons else ""))
        return data, summary

    def _detections(self, args: DetectionInput) -> tuple[Any, str]:
        if args.detection_id is not None:
            detail = self._services.detections.detail(args.detection_id, max_events=30)
            d = detail.detection
            return detail.model_dump(mode="json"), (
                f"detection {d.detection_id} on {d.host_name}: score {d.score:.2f}, "
                f"{detail.events_found}/{detail.events_requested} events found")
        host = validate_host_name(args.host_name) if args.host_name else None
        page = self._services.detections.list(window_minutes=args.window_minutes,
                                              flagged_only=True, host_name=host, limit=10)
        return page.model_dump(mode="json"), (
            f"{page.total} flagged windows in {args.window_minutes} min"
            + (f" for {host}" if host else ""))

    def _timeline(self, args: TimelineInput) -> tuple[Any, str]:
        timeline = self._services.detections.host_timeline(
            args.host_name, window_minutes=args.window_minutes, limit=args.limit)
        return timeline.model_dump(mode="json"), (
            f"{len(timeline.events)} events{' (truncated)' if timeline.events_truncated else ''}, "
            f"{len(timeline.detections)} detections for {timeline.host_name}")

    def _ledger(self, _: NoInput) -> tuple[Any, str]:
        status = self._services.cached_ledger()
        return status.model_dump(mode="json"), f"ledger {status.status.value}: {status.detail}"

    def _search(self, args: RunbookInput) -> tuple[Any, str]:
        if not self._runbooks.available:
            raise ToolError("runbook index unavailable: " + "; ".join(self._runbooks.errors or ["empty"]))
        hits = self._runbooks.search(args.query, limit=args.limit)
        for hit in hits:
            self.retrieved_sections.add((hit.source, hit.section))
        if not hits:
            return {"hits": [], "note": "no runbook section matched the query"}, "no matching runbook sections"
        return ({"hits": [h.model_dump() for h in hits]},
                "; ".join(f"{h.source} § {h.section}" for h in hits))
