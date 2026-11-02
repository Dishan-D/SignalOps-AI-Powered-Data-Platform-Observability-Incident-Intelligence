#!/usr/bin/env python3
"""Controlled data-quality incident, end to end, through the real stack.

Every value printed comes from the running API; nothing is hard-coded. Steps:

1. Baseline: API health and the current DLQ count for the window.
2. Inject a burst of invalid events onto logs.raw (scripts/inject_bad_events.py).
3. Wait until the operational metrics observe the rejected records in the DLQ.
4. Confirm the rule engine raises the dlq_spike candidate.
5. Start an investigation and wait for the report (or its failure).
6. Print observations, hypotheses, runbook citations and evidence.
7. Show that core processing is still advancing regardless of the LLM outcome.

    python scripts/demo_incident.py                      # uses the API's configured provider
    python scripts/demo_incident.py --expect-llm-failure # for the LLM-outage variant

Exit code 0 only if every step's expectation held.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent.parent
INCIDENT = "dlq_spike:logs.raw.dlq"


class Demo:
    def __init__(self, api: str, key: str, window: int) -> None:
        self.http = httpx.Client(base_url=api, timeout=20, headers={"x-api-key": key} if key else {})
        self.window = window

    def get(self, path: str, **params: Any) -> Any:
        response = self.http.get(path, params=params)
        response.raise_for_status()
        return response.json()

    def metric(self, payload: dict[str, Any], name: str) -> float | None:
        for m in payload.get("metrics", []):
            if m["name"] == name:
                return m["value"] if m["state"] == "ok" else None
        return payload.get(name, {}).get("value") if isinstance(payload.get(name), dict) else None


def step(n: int, text: str) -> None:
    print(f"\n[{n}] {text}")


def fail(text: str) -> int:
    print(f"    FAILED: {text}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--bootstrap", default="localhost:29092")
    parser.add_argument("--count", type=int, default=400)
    parser.add_argument("--window", type=int, default=15)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--expect-llm-failure", action="store_true")
    args = parser.parse_args()
    demo = Demo(args.api, args.api_key, args.window)

    step(1, "Baseline")
    health = demo.get("/api/ops/health")
    print(f"    pipeline {health['status']}: {health['summary']}")
    before = demo.get("/api/ops/dlq/summary", window_minutes=args.window)
    dlq_before = before["records_in_window"]["value"]
    if dlq_before is None:
        return fail(f"DLQ count unavailable: {before['records_in_window']['detail']}")
    metrics_before = demo.get("/api/ops/metrics", window_minutes=args.window)
    raw_before = demo.metric(metrics_before, "spark.raw_rows_processed")
    print(f"    DLQ records in last {args.window} min: {int(dlq_before)}; "
          f"Spark raw rows processed: {raw_before}")

    step(2, f"Injecting {args.count} invalid events onto logs.raw")
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "inject_bad_events.py"),
                             "--count", str(args.count), "--bootstrap", args.bootstrap],
                            capture_output=True, text=True)
    print("    " + (result.stdout.strip() or result.stderr.strip()))
    if result.returncode != 0:
        return fail("injection failed")

    step(3, "Waiting for the DLQ to reflect the rejected records (Spark trigger + DLQ write)")
    deadline = time.monotonic() + args.timeout
    summary: dict[str, Any] = {}
    while time.monotonic() < deadline:
        summary = demo.get("/api/ops/dlq/summary", window_minutes=args.window)
        now = summary["records_in_window"]["value"] or 0
        if now - dlq_before >= args.count:
            break
        time.sleep(5)
    else:
        return fail(f"DLQ grew by {(summary['records_in_window']['value'] or 0) - dlq_before}, "
                    f"expected {args.count}")
    ratio = summary["dlq_ratio"]
    print(f"    DLQ records: {int(summary['records_in_window']['value'])} "
          f"(+{int(summary['records_in_window']['value'] - dlq_before)}), ratio "
          f"{ratio['value']:.1%}" if ratio["state"] == "ok" else f"    ratio: {ratio['detail']}")
    print(f"    sampled reasons: {summary['sample_error_counts']}")

    step(4, "Incident candidates")
    incidents = demo.get("/api/ops/incidents", window_minutes=args.window)
    for c in incidents["candidates"]:
        print(f"    {c['incident_id']} [{c['severity']}] {c['title']}")
    if not any(c["incident_id"] == INCIDENT for c in incidents["candidates"]):
        return fail(f"{INCIDENT} not raised (rules skipped: {incidents['rules_skipped']})")

    step(5, "Starting an investigation")
    provider = demo.get("/api/ops/investigations")["provider"]
    print(f"    provider: {provider}")
    response = demo.http.post("/api/ops/investigate",
                              json={"incident_id": INCIDENT, "window_minutes": args.window})
    if response.status_code == 503:
        print(f"    investigations unavailable: {response.json()['error']['message']}")
        if not args.expect_llm_failure:
            return fail("investigation service unavailable")
        job = None
    else:
        response.raise_for_status()
        job_id = response.json()["job_id"]
        while True:
            job = demo.get(f"/api/ops/investigations/{job_id}")
            if job["status"] in {"succeeded", "failed"}:
                break
            time.sleep(2)

    step(6, "Result")
    if job is not None and job["status"] == "succeeded":
        report = job["report"]
        print(f"    [{report['severity']}] {report['summary']}")
        print(f"    generated by: {report['generated_by']}")
        for o in report["observations"]:
            print(f"    OBSERVED  {o['claim']}  ({', '.join(o['evidence_ids'])})")
        for c in report["potential_causes"]:
            print(f"    HYPOTHESIS [{c['confidence']}] {c['hypothesis']}  ({', '.join(c['supporting_evidence'])})")
        for r in report["runbooks"]:
            print(f"    RUNBOOK   {r['source']} § {r['section']}")
        for e in report["evidence"]:
            print(f"    EVIDENCE  {e['evidence_id']} {e['tool']} ok={e['ok']}: {e['summary'][:100]}")
        for n in report["validation_notes"]:
            print(f"    NOTE      {n}")
        if args.expect_llm_failure:
            return fail("expected the LLM to fail, but the investigation succeeded")
    elif job is not None:
        print(f"    investigation failed: {job['error']}")
        print(f"    evidence gathered before failure: {[e['tool'] for e in job['evidence']]}")
        if not args.expect_llm_failure:
            return fail("investigation failed")

    step(7, "Core pipeline still processing")
    time.sleep(15)
    health = demo.get("/api/ops/health")
    after = demo.get("/api/ops/metrics", window_minutes=args.window)
    spark = next(c for c in health["components"] if c["name"] == "spark")
    print(f"    health {health['status']}; spark {spark['status']}: {spark['detail']}")
    print(f"    Spark raw rows processed in window: {raw_before} -> "
          f"{demo.metric(after, 'spark.raw_rows_processed')}")
    if spark["status"] not in {"healthy", "degraded"}:
        return fail("Spark is not processing")
    print("\nDemo complete: every value above was read from the running API.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
