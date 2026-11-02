"""LLM providers behind a minimal session interface.

The agent loop talks to :class:`LLMSession` only, so it is tested with a
scripted fake and can run against Claude or the offline investigator without
change. A session owns its native message history: for Claude that means the
assistant's content blocks (including thinking blocks) are appended back
verbatim on every turn, as the API requires.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

from signalops.config import LLMSettings


class ProviderError(RuntimeError):
    """The provider could not complete a turn. ``kind`` is one of:
    ``unconfigured``, ``unavailable``, ``timeout``, ``refused``, ``bad_response``."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    input: Any


@dataclass(frozen=True)
class ToolResult:
    tool_call_id: str
    content: str
    is_error: bool = False


@dataclass
class ModelTurn:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"


class LLMSession(Protocol):
    def send(self, *, user_text: str | None = None, tool_results: list[ToolResult] | None = None,
             timeout: float) -> ModelTurn: ...


class LLMProvider(Protocol):
    name: str
    model: str | None
    uses_llm: bool

    def start(self, system: str, tools: list[dict[str, Any]]) -> LLMSession: ...


def _user_content(user_text: str | None, tool_results: list[ToolResult] | None) -> list[dict[str, Any]]:
    content: list[dict[str, Any]] = [
        {"type": "tool_result", "tool_use_id": r.tool_call_id, "content": r.content,
         **({"is_error": True} if r.is_error else {})}
        for r in tool_results or []
    ]
    if user_text:
        content.append({"type": "text", "text": user_text})
    return content


# --------------------------------------------------------------------------- #
# Claude                                                                       #
# --------------------------------------------------------------------------- #

class AnthropicProvider:
    name = "anthropic"
    uses_llm = True

    def __init__(self, settings: LLMSettings, client: Any = None) -> None:
        self.model: str | None = settings.model
        self._settings = settings
        if client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover - dependency is declared
                raise ProviderError("unconfigured", "the anthropic package is not installed") from exc
            if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
                raise ProviderError("unconfigured", "ANTHROPIC_API_KEY is not set")
            client = anthropic.Anthropic(max_retries=1, timeout=settings.request_timeout_seconds)
        self._client = client

    def start(self, system: str, tools: list[dict[str, Any]]) -> LLMSession:
        return _AnthropicSession(self._client, self._settings, system,
                                 [{**t, "strict": True} for t in tools])


class _AnthropicSession:
    def __init__(self, client: Any, settings: LLMSettings, system: str,
                 tools: list[dict[str, Any]]) -> None:
        self._client = client
        self._settings = settings
        self._system = system
        self._tools = tools
        self._messages: list[dict[str, Any]] = []

    def send(self, *, user_text: str | None = None, tool_results: list[ToolResult] | None = None,
             timeout: float) -> ModelTurn:
        import anthropic

        self._messages.append({"role": "user", "content": _user_content(user_text, tool_results)})
        kwargs: dict[str, Any] = {
            "model": self._settings.model,
            "max_tokens": self._settings.max_tokens,
            "system": self._system,
            "tools": self._tools,
            "messages": self._messages,
            "output_config": {"effort": self._settings.effort},
            "timeout": timeout,
        }
        try:
            if self._settings.server_fallbacks:
                response = self._client.beta.messages.create(
                    betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs)
            else:
                response = self._client.messages.create(**kwargs)
        except anthropic.APITimeoutError as exc:
            raise ProviderError("timeout", "Claude API request timed out") from exc
        except anthropic.AuthenticationError as exc:
            raise ProviderError("unconfigured", "Claude API rejected the credentials") from exc
        except anthropic.RateLimitError as exc:
            raise ProviderError("unavailable", "Claude API rate limit reached") from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderError("unavailable", "Claude API unreachable") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError("bad_response", f"Claude API error {exc.status_code}") from exc

        # The assistant turn goes back verbatim (thinking blocks included).
        self._messages.append({"role": "assistant", "content": response.content})
        if response.stop_reason == "refusal":
            return ModelTurn(text="", stop_reason="refusal")
        text = "".join(b.text for b in response.content if getattr(b, "type", None) == "text")
        calls = [ToolCall(id=b.id, name=b.name, input=b.input)
                 for b in response.content if getattr(b, "type", None) == "tool_use"]
        return ModelTurn(text=text, tool_calls=calls, stop_reason=response.stop_reason or "end_turn")


# --------------------------------------------------------------------------- #
# Offline (deterministic, no LLM)                                              #
# --------------------------------------------------------------------------- #

_RULE_HYPOTHESES: dict[str, list[str]] = {
    "dlq_spike": [
        "An upstream producer or schema change is emitting records that fail the '{reason}' "
        "validation rule.",
        "Test or malformed traffic was published to the raw topic.",
    ],
    "normalize_failures": [
        "Landed rows violate a database constraint or type in the normalisation transform.",
    ],
    "stream_query_failed": ["A downstream sink or the checkpoint used by the query is failing."],
    "stream_stalled": ["The Spark driver or one sink is blocked, or the listener cannot write telemetry."],
    "ledger_integrity": ["Evidence or ledger rows were modified after they were digested or sealed."],
    "ledger_seal_stalled": ["The sealer service is stopped or its maintenance cycles are failing."],
    "normalize_backlog": ["The sealer's normalisation step is not keeping up or is not running."],
    "anomaly_cluster": ["The host's event sequence diverges from benign training behaviour; "
                        "this may be malicious activity or new legitimate behaviour."],
}


class OfflineProvider:
    """A deterministic investigator for demos and environments without an API key.

    It drives the *same* agent loop and tools as Claude: it calls the incident's
    related tools plus a runbook search, then submits a report whose
    observations are mechanical restatements of the tool summaries. It does no
    reasoning and says so in every report it produces.
    """

    name = "offline"
    model: str | None = None
    uses_llm = False

    def start(self, system: str, tools: list[dict[str, Any]]) -> LLMSession:  # noqa: ARG002
        return _OfflineSession({t["name"] for t in tools})


class _OfflineSession:
    def __init__(self, tool_names: set[str]) -> None:
        self._tools = tool_names
        self._turn = 0
        self._context: dict[str, Any] = {}
        self._calls: dict[str, str] = {}

    def send(self, *, user_text: str | None = None, tool_results: list[ToolResult] | None = None,
             timeout: float) -> ModelTurn:  # noqa: ARG002 - nothing to time out
        self._turn += 1
        if self._turn == 1:
            self._context = _parse_context(user_text or "")
            incident = self._context.get("incident") or {}
            wanted = list(incident.get("related_tools") or ["get_pipeline_health", "get_pipeline_metrics"])
            if "search_runbooks" not in wanted:
                wanted.append("search_runbooks")
            window = int(self._context.get("window_minutes") or 60)
            calls = []
            for i, name in enumerate(n for n in wanted if n in self._tools):
                args: dict[str, Any] = {}
                if name in {"get_pipeline_metrics", "get_recent_failures", "get_dlq_summary"}:
                    args = {"window_minutes": window}
                elif name == "search_runbooks":
                    args = {"query": incident.get("runbook_query")
                            or self._context.get("question") or "pipeline health", "limit": 2}
                elif name in {"get_host_timeline", "get_detection_details"}:
                    if incident.get("rule") != "anomaly_cluster":
                        continue
                    args = {"host_name": incident.get("scope"), "window_minutes": window}
                calls.append(ToolCall(id=f"offline-{i}", name=name, input=args))
                self._calls[f"offline-{i}"] = name
            return ModelTurn(text="", tool_calls=calls, stop_reason="tool_use")

        if self._turn == 2:
            return ModelTurn(text="", tool_calls=[ToolCall(
                id="offline-report", name="submit_report",
                input=self._report(tool_results or []))], stop_reason="tool_use")
        return ModelTurn(text="Report submitted.", stop_reason="end_turn")

    def _report(self, results: list[ToolResult]) -> dict[str, Any]:
        incident = self._context.get("incident") or {}
        observations, citations, ok_ids, missing = [], [], [], []
        for r in results:
            payload = json.loads(r.content)
            eid, tool = payload.get("evidence_id"), self._calls.get(r.tool_call_id, "tool")
            if r.is_error:
                missing.append(f"{tool} failed: {payload.get('error')}")
                continue
            ok_ids.append(eid)
            observations.append({"claim": f"{tool}: {payload.get('summary')}", "evidence_ids": [eid]})
            for hit in (payload.get("data") or {}).get("hits", [])[:2]:
                citations.append({"source": hit["source"], "section": hit["section"],
                                  "relevance": f"matched terms: {', '.join(hit['matched_terms'][:5])}"})
        support = (["E0"] if incident else []) + ok_ids[:1]
        reason = _dominant_reason(incident)
        causes = [{"hypothesis": h.format(reason=reason), "supporting_evidence_ids": support or ["E0"],
                   "confidence": "low"}
                  for h in _RULE_HYPOTHESES.get(incident.get("rule", ""), [])] if support else []
        title = incident.get("title") or self._context.get("question") or "operational question"
        return {
            "summary": f"Deterministic evidence summary for: {title}. Observations restate tool "
                       "results; causes are rule-based templates, not analysis.",
            "observations": observations,
            "potential_causes": causes,
            "runbook_citations": citations,
            "recommended_steps": ["Follow the diagnostic steps in the cited runbook sections.",
                                  "Verify each observation against the linked evidence."],
            "missing_information": missing,
            "limitations": ["Generated by the offline investigator: no language model was used and "
                            "no correlation or reasoning was performed."],
        }


def _parse_context(text: str) -> dict[str, Any]:
    marker = "<investigation_context>"
    if marker in text:
        body = text.split(marker, 1)[1].split("</investigation_context>", 1)[0]
        try:
            parsed = json.loads(body)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


def _dominant_reason(incident: dict[str, Any]) -> str:
    for fact in incident.get("facts") or []:
        name = fact.get("name", "")
        if name.startswith("dlq.sample.reason."):
            return name.removeprefix("dlq.sample.reason.")
    return "unknown"


def build_provider(settings: LLMSettings) -> LLMProvider:
    if settings.provider == "anthropic":
        return AnthropicProvider(settings)
    if settings.provider == "offline":
        return OfflineProvider()
    raise ProviderError("unconfigured",
                        "investigations are disabled (set SIGNALOPS_LLM_PROVIDER=anthropic with "
                        "ANTHROPIC_API_KEY, or SIGNALOPS_LLM_PROVIDER=offline)")
