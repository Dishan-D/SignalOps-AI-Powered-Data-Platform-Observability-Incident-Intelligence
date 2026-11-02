"""Operational API: status codes, validation, errors, auth, investigations."""

from __future__ import annotations

import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

from forensics.common.config import ConfigError
from signalops.api.app import create_app
from signalops.config import LLMSettings
from signalops.investigation.provider import OfflineProvider, ProviderError
from signalops.retrieval.runbooks import RunbookIndex
from signalops.services import OpsServices
from signalops.services import detections as det_sql
from signalops.sources.errors import DataSourceError
from tests.signalops.conftest import inject_dlq_burst, make_settings
from tests.signalops.fakes import FakeDatabase, FakeKafka, ScriptedProvider, ago, call, tools_turn


def client_for(services: OpsServices, runbooks: RunbookIndex, *, provider: Any = None,
               **settings: Any) -> TestClient:
    s = make_settings(**settings)
    if provider is None:
        def factory() -> Any:
            raise ProviderError("unconfigured", "investigations are disabled")
    else:
        def factory() -> Any:
            return provider
    services.settings = s
    return TestClient(create_app(s, services=services, runbooks=runbooks, provider_factory=factory))


@pytest.fixture
def api(services: OpsServices, runbooks: RunbookIndex) -> TestClient:
    return client_for(services, runbooks)


def wait_for(client: TestClient, job_id: str, *, timeout: float = 10) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/ops/investigations/{job_id}").json()
        if job["status"] in {"succeeded", "failed"}:
            return job
        time.sleep(0.05)
    raise AssertionError("investigation did not finish")


# --------------------------------------------------------------------------- #
# Probes and health                                                            #
# --------------------------------------------------------------------------- #


def test_probes(api: TestClient, db: FakeDatabase) -> None:
    assert api.get("/api/ops/livez").json() == {"status": "alive"}
    assert api.get("/api/ops/readyz").status_code == 200
    db.down = DataSourceError("postgres", "cannot connect", unavailable=True)
    assert api.get("/api/ops/readyz").status_code == 503
    assert api.get("/api/ops/livez").status_code == 200  # liveness is not readiness


def test_health_ok(api: TestClient) -> None:
    body = api.get("/api/ops/health").json()
    assert body["status"] == "healthy"
    assert {c["name"] for c in body["components"]} == {"postgres", "kafka", "spark", "detector", "ledger"}


def test_health_degraded_component(api: TestClient, kafka: FakeKafka) -> None:
    del kafka.topic_partitions["logs.raw.dlq"]
    body = api.get("/api/ops/health").json()
    assert body["status"] == "degraded"
    assert "kafka: degraded" in body["summary"]


def test_health_does_not_depend_on_llm(services: OpsServices, runbooks: RunbookIndex) -> None:
    calls = []

    def exploding_factory() -> Any:
        calls.append(1)
        raise RuntimeError("LLM must not be touched by health")

    app = create_app(make_settings(), services=services, runbooks=runbooks,
                     provider_factory=exploding_factory)
    client = TestClient(app)
    assert client.get("/api/ops/health").status_code == 200
    assert client.get("/api/ops/metrics").status_code == 200
    assert calls == []


def test_request_id_is_propagated(api: TestClient) -> None:
    response = api.get("/api/ops/livez", headers={"x-request-id": "abc123"})
    assert response.headers["x-request-id"] == "abc123"


# --------------------------------------------------------------------------- #
# Reads                                                                        #
# --------------------------------------------------------------------------- #


def test_metrics(api: TestClient) -> None:
    body = api.get("/api/ops/metrics", params={"window_minutes": 15}).json()
    assert body["window_minutes"] == 15
    names = {m["name"] for m in body["metrics"]}
    assert {"kafka.logs.raw.records_in_window", "spark.raw_rows_processed", "latency.landing.p95"} <= names


@pytest.mark.parametrize("params", [{"window_minutes": 0}, {"window_minutes": 999999},
                                    {"window_minutes": "abc"}])
def test_invalid_query_parameters(api: TestClient, params: dict[str, Any]) -> None:
    response = api.get("/api/ops/metrics", params=params)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


def test_dependency_failure_is_503_with_source(api: TestClient, db: FakeDatabase) -> None:
    db.on(det_sql.LIST_SQL, DataSourceError("postgres", "statement timeout", unavailable=False))
    response = api.get("/api/ops/detections")
    assert response.status_code == 503
    assert response.json()["error"] == {"code": "dependency_error", "message": "statement timeout",
                                        "source": "postgres"}


def test_detections_and_detail(api: TestClient, db: FakeDatabase) -> None:
    row = {"detection_id": 7, "host_name": "web-01", "window_start": ago(minutes=10),
           "window_end": ago(minutes=9), "scored_at": ago(minutes=8), "score": 1.7, "flagged": True,
           "signals": {"max_nll": 9.1}, "model_version": "m1", "event_count": 0}
    db.on(det_sql.LIST_SQL, [row])
    db.on(det_sql.COUNT_SQL, {"n": 1})
    body = api.get("/api/ops/detections", params={"limit": 5}).json()
    assert body["total"] == 1 and body["items"][0]["detection_id"] == 7
    db.on(det_sql.DETAIL_SQL, {**row, "thresholds": {"max_nll": 5.0}, "event_ids": []})
    assert api.get("/api/ops/detections/7").json()["thresholds"] == {"max_nll": 5.0}
    db.on(det_sql.DETAIL_SQL, None)
    assert api.get("/api/ops/detections/8").status_code == 404
    assert api.get("/api/ops/detections/0").status_code == 422
    assert api.get("/api/ops/detections", params={"limit": 501}).status_code == 422


def test_host_timeline(api: TestClient, db: FakeDatabase) -> None:
    db.on(det_sql.HOST_SQL, {"host_id": 1})
    db.on(det_sql.HOST_EVENTS_SQL, [{"event_id": "e1", "occurred_at": ago(minutes=2), "category": "file"}])
    db.on(det_sql.HOST_DETECTIONS_SQL, [])
    body = api.get("/api/ops/hosts/web-01/timeline").json()
    assert body["host_name"] == "web-01" and len(body["events"]) == 1
    assert api.get("/api/ops/hosts/bad host!/timeline").status_code == 422
    db.on(det_sql.HOST_SQL, None)
    db.on(det_sql.HOST_DETECTION_EXISTS_SQL, None)
    assert api.get("/api/ops/hosts/ghost/timeline").status_code == 404


def test_dlq_summary_and_incidents(api: TestClient, kafka: FakeKafka) -> None:
    inject_dlq_burst(kafka, count=300)
    dlq = api.get("/api/ops/dlq/summary").json()
    assert dlq["records_in_window"]["value"] == 300
    incidents = api.get("/api/ops/incidents").json()
    assert [c["incident_id"] for c in incidents["candidates"]] == ["dlq_spike:logs.raw.dlq"]
    assert api.get("/api/ops/incidents/dlq_spike:logs.raw.dlq").status_code == 200
    assert api.get("/api/ops/incidents/anomaly_cluster:nobody").status_code == 404
    assert api.get("/api/ops/incidents/not-an-id").status_code == 422


def test_ledger_status(api: TestClient) -> None:
    body = api.get("/api/ops/ledger/status").json()
    assert body["status"] == "healthy" and body["unsealed_events"] == 40 and body["limitations"]


def test_runbook_search(api: TestClient) -> None:
    hits = api.get("/api/ops/runbooks/search", params={"q": "unknown_category"}).json()
    assert hits[0]["source"] == "runbooks/schema-validation-errors.md"
    assert api.get("/api/ops/runbooks/search", params={"q": ""}).status_code == 422


def test_operational_routes_are_read_only(api: TestClient) -> None:
    for path in ("/api/ops/health", "/api/ops/metrics", "/api/ops/detections", "/api/ops/ledger/status"):
        assert api.post(path).status_code == 405
        assert api.delete(path).status_code == 405


# --------------------------------------------------------------------------- #
# Auth                                                                         #
# --------------------------------------------------------------------------- #


def test_api_key_required_when_configured(services: OpsServices, runbooks: RunbookIndex) -> None:
    client = client_for(services, runbooks, api_key="s3cret")
    assert client.get("/api/ops/health").status_code == 401
    assert client.get("/api/ops/health", headers={"x-api-key": "wrong"}).status_code == 401
    assert client.get("/api/ops/health", headers={"x-api-key": "s3cret"}).status_code == 200
    assert client.get("/api/ops/livez").status_code == 200  # probes stay open


def test_non_local_environment_requires_api_key(services: OpsServices, runbooks: RunbookIndex) -> None:
    with pytest.raises(ConfigError):
        create_app(make_settings(environment="production"), services=services, runbooks=runbooks)


# --------------------------------------------------------------------------- #
# Investigations                                                               #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("body", [{}, {"window_minutes": 60}, {"incident_id": "garbage"},
                                  {"question": "x" * 2000}, {"question": "ok?", "window_minutes": 0}])
def test_invalid_investigation_requests(services: OpsServices, runbooks: RunbookIndex,
                                        body: dict[str, Any]) -> None:
    client = client_for(services, runbooks, provider=OfflineProvider())
    assert client.post("/api/ops/investigate", json=body).status_code == 422


def test_investigation_unavailable_without_provider(api: TestClient) -> None:
    response = api.post("/api/ops/investigate", json={"question": "what is wrong?"})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "investigations_unavailable"
    assert api.get("/api/ops/investigations").json()["provider"]["enabled"] is False


def test_unknown_incident_is_404(services: OpsServices, runbooks: RunbookIndex) -> None:
    client = client_for(services, runbooks, provider=OfflineProvider())
    response = client.post("/api/ops/investigate", json={"incident_id": "dlq_spike:logs.raw.dlq"})
    assert response.status_code == 404


def test_investigation_job_lifecycle(services: OpsServices, runbooks: RunbookIndex,
                                     kafka: FakeKafka) -> None:
    inject_dlq_burst(kafka, count=300)
    client = client_for(services, runbooks, provider=OfflineProvider())
    started = client.post("/api/ops/investigate", json={"incident_id": "dlq_spike:logs.raw.dlq"})
    assert started.status_code == 202
    job = wait_for(client, started.json()["job_id"])
    assert job["status"] == "succeeded"
    assert job["report"]["incident_id"] == "dlq_spike:logs.raw.dlq"
    assert job["report"]["generated_by"]["uses_llm"] is False
    assert client.get("/api/ops/investigations/" + "0" * 32).status_code == 404
    assert client.get("/api/ops/investigations/not-hex").status_code == 422


def test_llm_outage_fails_job_but_not_platform(services: OpsServices, runbooks: RunbookIndex) -> None:
    provider = ScriptedProvider([tools_turn(call("get_pipeline_health")),
                                 ProviderError("timeout", "Claude API request timed out")])
    client = client_for(services, runbooks, provider=provider)
    started = client.post("/api/ops/investigate", json={"question": "is the pipeline ok?"})
    job = wait_for(client, started.json()["job_id"])
    assert job["status"] == "failed" and "timed out" in job["error"]
    assert job["report"] is None  # no fabricated report
    assert [e["tool"] for e in job["evidence"]] == ["get_pipeline_health"]
    assert client.get("/api/ops/health").json()["status"] == "healthy"


def test_investigation_settings_round_trip() -> None:
    assert LLMSettings().model == "claude-opus-5-5"
