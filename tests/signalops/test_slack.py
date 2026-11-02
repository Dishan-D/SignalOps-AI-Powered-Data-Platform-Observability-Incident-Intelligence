"""Slack /ops command: signatures, staleness, routing, auth, duplicates, async work."""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from typing import Any
from urllib.parse import urlencode

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from signalops.config import SlackSettings
from signalops.investigation import InvestigationJobs, Investigator
from signalops.investigation.provider import OfflineProvider, ProviderError
from signalops.retrieval.runbooks import RunbookIndex
from signalops.services import OpsServices
from signalops.slack.commands import create_slack_router, is_slack_response_url
from tests.signalops.conftest import inject_dlq_burst, make_settings
from tests.signalops.fakes import FakeKafka

SECRET = "test-signing-secret"
RESPONSE_URL = "https://hooks.slack.com/commands/T1/123/abc"


def sign(body: bytes, timestamp: int, secret: str = SECRET) -> str:
    base = f"v0:{timestamp}:".encode() + body
    return "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()


class Harness:
    def __init__(self, services: OpsServices, runbooks: RunbookIndex, *, enabled: bool = True,
                 provider_ok: bool = True, allowed: tuple[str, ...] = ("U_ADMIN",)) -> None:
        self.posts: list[tuple[str, dict[str, Any]]] = []
        settings = make_settings(slack=SlackSettings(signing_secret=SECRET if enabled else "",
                                                     allowed_user_ids=allowed))
        from signalops.config import LLMSettings

        investigator = Investigator(services, runbooks, OfflineProvider, LLMSettings(provider="offline"))
        self.jobs = InvestigationJobs(investigator)

        def status() -> dict[str, Any]:
            if provider_ok:
                return {"enabled": True, "provider": "offline", "model": None}
            return {"enabled": False, "reason": str(ProviderError("unconfigured", "no key"))}

        app = FastAPI()
        app.include_router(create_slack_router(settings, services, runbooks, self.jobs, status,
                                               post=lambda url, payload: self.posts.append((url, payload))))
        self.client = TestClient(app)

    def send(self, text: str, *, user: str = "U_ADMIN", timestamp: int | None = None,
             secret: str = SECRET, response_url: str = RESPONSE_URL, trigger: str | None = None,
             headers: dict[str, str] | None = None) -> Any:
        form = {"command": "/ops", "text": text, "user_id": user, "channel_id": "C1",
                "response_url": response_url, "trigger_id": trigger or f"trig-{uuid.uuid4().hex}"}
        body = urlencode(form).encode()
        ts = timestamp if timestamp is not None else int(time.time())
        return self.client.post("/slack/commands", content=body, headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": str(ts), "x-slack-signature": sign(body, ts, secret),
            **(headers or {})})

    def wait_posts(self, n: int, timeout: float = 10) -> list[tuple[str, dict[str, Any]]]:
        deadline = time.monotonic() + timeout
        while len(self.posts) < n and time.monotonic() < deadline:
            time.sleep(0.05)
        return self.posts


@pytest.fixture
def slack(services: OpsServices, runbooks: RunbookIndex) -> Harness:
    return Harness(services, runbooks)


def test_valid_signature_health(slack: Harness) -> None:
    response = slack.send("health")
    assert response.status_code == 200 and "Working on" in response.json()["text"]
    [(url, payload)] = slack.wait_posts(1)
    assert url == RESPONSE_URL and "Pipeline healthy" in payload["text"]
    assert payload["response_type"] == "ephemeral"


def test_invalid_signature_rejected(slack: Harness) -> None:
    assert slack.send("health", secret="wrong").status_code == 401
    assert slack.posts == []


def test_stale_timestamp_rejected(slack: Harness) -> None:
    assert slack.send("health", timestamp=int(time.time()) - 600).status_code == 401


def test_disabled_without_signing_secret(services: OpsServices, runbooks: RunbookIndex) -> None:
    harness = Harness(services, runbooks, enabled=False)
    assert harness.send("health").status_code == 404


def test_help_and_unknown_command(slack: Harness) -> None:
    assert "/ops health" in slack.send("").json()["text"]
    assert "Unknown command" in slack.send("reboot-prod").json()["text"]
    assert slack.posts == []


def test_missing_arguments(slack: Harness) -> None:
    assert "Usage" in slack.send("runbook").json()["text"]
    assert "Usage" in slack.send("investigate").json()["text"]
    assert "rule>:<scope" in slack.send("investigate ../../etc").json()["text"]


def test_sensitive_commands_need_allow_list(slack: Harness) -> None:
    assert "not authorised" in slack.send("incidents", user="U_RANDOM").json()["text"]
    assert "not authorised" in slack.send("investigate dlq_spike:logs.raw.dlq", user="U_RANDOM").json()["text"]
    assert slack.posts == []
    slack.send("runbook dlq", user="U_RANDOM")  # non-sensitive: allowed
    assert slack.wait_posts(1)


def test_duplicate_requests_processed_once(slack: Harness) -> None:
    slack.send("health", trigger="same")
    second = slack.send("health", trigger="same")
    assert "Already processing" in second.json()["text"]
    assert "Already processing" in slack.send("health", headers={"x-slack-retry-num": "1"}).json()["text"]
    time.sleep(0.3)
    assert len(slack.posts) == 1


def test_response_url_must_be_slack(slack: Harness) -> None:
    response = slack.send("health", response_url="https://attacker.example/hook")
    assert response.status_code == 400 and slack.posts == []
    assert not is_slack_response_url("http://hooks.slack.com/x")
    assert not is_slack_response_url("https://hooks.slack.com.evil.io/x")
    assert is_slack_response_url(RESPONSE_URL)


def test_runbook_search(slack: Harness) -> None:
    slack.send("runbook unknown_category")
    [(_, payload)] = slack.wait_posts(1)
    assert "schema-validation-errors.md" in payload["text"]


def test_incidents_lists_candidates(slack: Harness, kafka: FakeKafka) -> None:
    inject_dlq_burst(kafka, count=300)
    slack.send("incidents")
    [(_, payload)] = slack.wait_posts(1)
    assert "dlq_spike:logs.raw.dlq" in payload["text"] and "not confirmed" in payload["text"]


def test_async_investigation_posts_start_and_result(slack: Harness, kafka: FakeKafka) -> None:
    inject_dlq_burst(kafka, count=300)
    ack = slack.send("investigate dlq_spike:logs.raw.dlq")
    assert "Starting investigation" in ack.json()["text"]
    posts = slack.wait_posts(2)
    assert "started" in posts[0][1]["text"]
    assert "*Investigation*" in posts[1][1]["text"] and "offline" in posts[1][1]["text"]


def test_investigation_of_inactive_incident(slack: Harness) -> None:
    slack.send("investigate dlq_spike:logs.raw.dlq")
    [(_, payload)] = slack.wait_posts(1)
    assert "not an active incident candidate" in payload["text"]


def test_investigation_when_provider_unavailable(services: OpsServices, runbooks: RunbookIndex,
                                                 kafka: FakeKafka) -> None:
    inject_dlq_burst(kafka, count=300)
    harness = Harness(services, runbooks, provider_ok=False)
    harness.send("investigate dlq_spike:logs.raw.dlq")
    [(_, payload)] = harness.wait_posts(1)
    assert "Investigations unavailable" in payload["text"]


def test_backend_failure_reported(slack: Harness, kafka: FakeKafka) -> None:
    kafka.down = True
    slack.send("health")
    [(_, payload)] = slack.wait_posts(1)
    assert "kafka" in payload["text"] and "unavailable" in payload["text"]
