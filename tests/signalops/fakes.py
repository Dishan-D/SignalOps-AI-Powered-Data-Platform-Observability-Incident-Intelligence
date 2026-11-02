"""In-memory stand-ins for Postgres, Kafka and the LLM.

``FakeDatabase`` answers by SQL *constant*: tests register a response (rows, a
callable, or an exception) for the exact module-level SQL string a service
uses. An unregistered query fails the test loudly, so a service cannot silently
start issuing SQL nobody has thought about.
"""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable
from typing import Any

from signalops.investigation.provider import ModelTurn, ToolCall, ToolResult
from signalops.sources.errors import DataSourceError
from signalops.sources.kafka import KafkaRecord

NOW = dt.datetime.now(tz=dt.timezone.utc)


def ago(**kwargs: float) -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(**kwargs)


class FakeDatabase:
    def __init__(self) -> None:
        self.responses: dict[str, Any] = {}
        self.calls: list[tuple[str, Any]] = []
        self.down: DataSourceError | None = None

    def on(self, sql: str, response: Any) -> FakeDatabase:
        self.responses[sql] = response
        return self

    def _answer(self, sql: str, params: Any) -> Any:
        self.calls.append((sql, params))
        if self.down is not None:
            raise self.down
        if sql not in self.responses:
            raise AssertionError(f"unexpected SQL:\n{sql}")
        response = self.responses[sql]
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return response(params)
        return response

    def fetch_all(self, sql: str, params: Any = ()) -> list[dict[str, Any]]:
        result = self._answer(sql, params)
        return list(result or [])

    def fetch_one(self, sql: str, params: Any = ()) -> dict[str, Any] | None:
        result = self._answer(sql, params)
        if isinstance(result, list):
            return result[0] if result else None
        return result

    def ping(self) -> None:
        if self.down is not None:
            raise self.down

    def params_for(self, sql: str) -> list[Any]:
        return [p for s, p in self.calls if s == sql]


class FakeKafka:
    def __init__(self) -> None:
        self.topic_partitions: dict[str, int] = {}
        self.marks: dict[str, dict[int, tuple[int, int]]] = {}
        self.since: dict[str, dict[int, int]] = {}
        self.records: dict[str, list[KafkaRecord]] = {}
        self.down = False
        self.tail_calls: list[tuple[str, int]] = []

    def _check(self) -> None:
        if self.down:
            raise DataSourceError("kafka", "broker unreachable", unavailable=True)

    def topics(self) -> dict[str, int]:
        self._check()
        return dict(self.topic_partitions)

    def watermarks(self, topic: str) -> dict[int, tuple[int, int]]:
        self._check()
        if topic not in self.marks:
            raise DataSourceError("kafka", f"topic {topic!r} does not exist", unavailable=False)
        return dict(self.marks[topic])

    def offsets_at(self, topic: str, timestamp_ms: int) -> dict[int, int]:
        self._check()
        return dict(self.since.get(topic, {}))

    def tail(self, topic: str, per_partition: int, *, timeout_seconds: float) -> list[KafkaRecord]:
        self._check()
        self.tail_calls.append((topic, per_partition))
        return list(self.records.get(topic, []))


def dlq_record(offset: int, error: str, *, payload: str = '{"event_id":"x"}', partition: int = 0,
               age_seconds: float = 30) -> KafkaRecord:
    ts = int((dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(seconds=age_seconds)).timestamp() * 1000)
    body = {"error": error, "source_topic": "logs.raw", "source_partition": partition,
            "source_offset": offset, "rejected_at": "2026-10-23T10:00:00.000Z", "payload": payload}
    return KafkaRecord(partition=partition, offset=offset, timestamp_ms=ts,
                       value=json.dumps(body).encode())


TurnFn = Callable[[list[ToolResult], str | None], ModelTurn]


class ScriptedProvider:
    """A fake LLM: each turn is a function of the tool results it just received."""

    name = "scripted"
    model = "scripted-model"
    uses_llm = True

    def __init__(self, turns: list[TurnFn | ModelTurn | Exception]) -> None:
        self.turns = turns
        self.sessions: list[ScriptedSession] = []

    def start(self, system: str, tools: list[dict[str, Any]]) -> ScriptedSession:
        session = ScriptedSession(self.turns, system, tools)
        self.sessions.append(session)
        return session


class ScriptedSession:
    def __init__(self, turns: list[Any], system: str, tools: list[dict[str, Any]]) -> None:
        self.turns = list(turns)
        self.system = system
        self.tools = tools
        self.received: list[tuple[str | None, list[ToolResult]]] = []

    def send(self, *, user_text: str | None = None, tool_results: list[ToolResult] | None = None,
             timeout: float) -> ModelTurn:
        self.received.append((user_text, list(tool_results or [])))
        if not self.turns:
            return ModelTurn(text="(no more scripted turns)")
        step = self.turns.pop(0)
        if isinstance(step, Exception):
            raise step
        if isinstance(step, ModelTurn):
            return step
        return step(list(tool_results or []), user_text)


def call(name: str, args: dict[str, Any] | None = None, call_id: str | None = None) -> ToolCall:
    return ToolCall(id=call_id or f"call-{name}", name=name, input=args or {})


def tools_turn(*calls: ToolCall) -> ModelTurn:
    return ModelTurn(text="", tool_calls=list(calls), stop_reason="tool_use")


def results_by_tool(results: list[ToolResult]) -> dict[str, dict[str, Any]]:
    out = {}
    for r in results:
        payload = json.loads(r.content)
        out[payload.get("tool", r.tool_call_id)] = payload
    return out
