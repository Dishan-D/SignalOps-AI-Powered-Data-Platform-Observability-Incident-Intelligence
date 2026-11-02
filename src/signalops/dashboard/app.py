"""SignalOps dashboard.

    streamlit run src/signalops/dashboard/app.py

Reads the operational API only (SIGNALOPS_API_URL, SIGNALOPS_API_KEY). Every
number on screen comes from an API response and is shown with the time it was
measured; anything the API could not measure is shown as "—" with the reason.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

if __package__ in (None, ""):  # `streamlit run path/to/app.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import plotly.graph_objects as go
import streamlit as st

from signalops.dashboard.data import (
    SERIES_COLORS,
    SEVERITY_ICON,
    ApiClient,
    ApiResult,
    age_seconds,
    component_rows,
    dig,
    humanize_age,
    incident_options,
    is_stale,
    metric_display,
    metrics_by_name,
    series_by_name,
    series_note,
    series_points,
    status_label,
)

st.set_page_config(page_title="SignalOps", page_icon="📡", layout="wide")

REFRESH_SECONDS = 15


@st.cache_resource
def client() -> ApiClient:
    return ApiClient()


@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def fetch(path: str, **params: Any) -> ApiResult:
    return client().get(path, **params)


def show_error(result: ApiResult, what: str) -> None:
    st.error(f"{what} unavailable: {result.error}")


def freshness(stamp: Any, max_age: float = REFRESH_SECONDS * 4) -> None:
    age = age_seconds(stamp)
    text = f"measured {humanize_age(age)}"
    if is_stale(stamp, max_age):
        st.warning(f"Stale data — {text}.")
    else:
        st.caption(text)


def metric_tile(column: Any, label: str, metric: dict[str, Any] | None) -> None:
    value, note = metric_display(metric)
    column.metric(label, value, help=note or None)
    if value == "—" and note:
        column.caption(note[:120])


def line_chart(title: str, series: list[tuple[str, dict[str, Any] | None]], y_title: str) -> None:
    fig = go.Figure()
    notes = []
    for i, (label, s) in enumerate(series):
        points = series_points(s)
        if points is None:
            notes.append(f"{label}: {series_note(s)}")
            continue
        xs, ys = points
        fig.add_trace(go.Scatter(x=xs, y=ys, mode="lines", name=label,
                                 line={"width": 2, "color": SERIES_COLORS[i % len(SERIES_COLORS)]},
                                 hovertemplate=f"{label}: %{{y:,.0f}}<br>%{{x|%H:%M}} UTC<extra></extra>"))
    st.markdown(f"**{title}**")
    if fig.data:
        fig.update_layout(height=260, margin={"l": 10, "r": 10, "t": 10, "b": 10},
                          hovermode="x unified", yaxis_title=y_title,
                          showlegend=len(fig.data) > 1,
                          legend={"orientation": "h", "y": 1.12, "x": 0})
        fig.update_xaxes(showgrid=False)
        st.plotly_chart(fig, width="stretch", theme="streamlit")
    for note in notes:
        st.caption(f"Not plotted — {note}")


# --------------------------------------------------------------------------- #
# Layout                                                                       #
# --------------------------------------------------------------------------- #

st.title("📡 SignalOps")
top = st.columns([3, 1, 1])
top[0].caption(f"Operational view of the forensics streaming pipeline · API {client().base_url}")
window = top[1].selectbox("Window", [15, 60, 240, 1440], index=1,
                          format_func=lambda m: f"last {m} min" if m < 1440 else "last 24 h")
if top[2].button("Refresh now"):
    fetch.clear()

tabs = st.tabs(["Health", "Ingestion & processing", "Data quality", "Anomalies",
                "Evidence integrity", "Investigate"])

# -- Health -------------------------------------------------------------------
with tabs[0]:
    health = fetch("/api/ops/health")
    if not health.ok:
        show_error(health, "Health")
    else:
        h = health.data
        st.subheader(f"Pipeline: {status_label(h.get('status'))}")
        st.write(h.get("summary", ""))
        freshness(h.get("checked_at"))
        st.dataframe(component_rows(h), width="stretch", hide_index=True)
    incidents = fetch("/api/ops/incidents", window_minutes=window)
    st.subheader("Incident candidates")
    if not incidents.ok:
        show_error(incidents, "Incident candidates")
    else:
        candidates = dig(incidents.data, "candidates", default=[])
        st.caption(dig(incidents.data, "policy", default=""))
        if not candidates:
            st.success(f"No rule matched in the last {window} minutes.")
        for c in candidates:
            sev = c.get("severity", "unknown")
            st.markdown(f"{SEVERITY_ICON.get(sev, '⚪')} **{c.get('title')}** — `{c.get('incident_id')}` "
                        f"· {sev} ({c.get('severity_reason', '')})")
        for skipped in dig(incidents.data, "rules_skipped", default=[]):
            st.warning(f"Rule not evaluated — {skipped}")

# -- Ingestion & processing -----------------------------------------------------
metrics = fetch("/api/ops/metrics", window_minutes=window)
with tabs[1]:
    if not metrics.ok:
        show_error(metrics, "Metrics")
    else:
        m = metrics_by_name(metrics.data)
        series = series_by_name(metrics.data)
        freshness(metrics.data.get("generated_at"))
        cols = st.columns(4)
        metric_tile(cols[0], "Raw records (Kafka)", m.get("kafka.logs.raw.records_in_window"))
        metric_tile(cols[1], "Processed by Spark", m.get("spark.raw_rows_processed"))
        metric_tile(cols[2], "Landed in Postgres", m.get("postgres.raw_events.landed_in_window"))
        metric_tile(cols[3], "Spark offset lag", m.get("spark.max_offsets_behind_latest"))
        cols = st.columns(4)
        metric_tile(cols[0], "Landing latency p50", m.get("latency.landing.p50"))
        metric_tile(cols[1], "Landing latency p95", m.get("latency.landing.p95"))
        metric_tile(cols[2], "Normalisation pending", m.get("postgres.normalize_pending"))
        metric_tile(cols[3], "Processing rate", m.get("spark.processed_rows_per_second"))
        bucket = metrics.data.get("bucket_minutes")
        line_chart(f"Records per {bucket}-minute bucket",
                   [("Spark input (raw)", series.get("spark.raw_rows_processed")),
                    ("Landed in Postgres", series.get("postgres.landed")),
                    ("Dead-lettered", series.get("spark.dlq_rows_written"))], "records")
        line_chart("Spark offsets behind latest (max per bucket)",
                   [("Offsets behind", series.get("spark.offsets_behind_latest"))], "offsets")
        for note in metrics.data.get("notes", []):
            st.caption(note)
        st.markdown("**Streaming queries**")
        st.dataframe([
            {"query": q.get("query_name"), "status": q.get("status"),
             "last event": humanize_age(q.get("seconds_since_event")),
             "stale": q.get("stale"), "exception": (q.get("exception") or "")[:120]}
            for q in metrics.data.get("stream_queries", []) if isinstance(q, dict)
        ], width="stretch", hide_index=True)

# -- Data quality ----------------------------------------------------------------
with tabs[2]:
    dlq = fetch("/api/ops/dlq/summary", window_minutes=window)
    if not dlq.ok:
        show_error(dlq, "DLQ summary")
    else:
        d = dlq.data
        freshness(d.get("generated_at"))
        cols = st.columns(4)
        metric_tile(cols[0], "Dead-lettered (window)", d.get("records_in_window"))
        metric_tile(cols[1], "DLQ ratio", d.get("dlq_ratio"))
        metric_tile(cols[2], "Retained in DLQ topic", d.get("retained_records"))
        metric_tile(cols[3], "Normalisation failures", d.get("normalize_failures_in_window"))
        counts = d.get("sample_error_counts") or {}
        if counts:
            st.markdown(f"**Validation failure reasons** (sample of {d.get('sample_size')} newest records"
                        f"{'' if d.get('sample_covers_window') else ', may not cover the whole window'})")
            fig = go.Figure(go.Bar(x=list(counts.values()), y=list(counts.keys()), orientation="h",
                                   marker={"color": SERIES_COLORS[1]},
                                   hovertemplate="%{y}: %{x:,}<extra></extra>"))
            fig.update_layout(height=60 + 34 * len(counts), margin={"l": 10, "r": 10, "t": 10, "b": 10},
                              yaxis={"autorange": "reversed"}, xaxis_title="records")
            st.plotly_chart(fig, width="stretch", theme="streamlit")
        if metrics.ok:
            line_chart("Dead-lettered vs normalisation failures",
                       [("Dead-lettered (Spark)", series_by_name(metrics.data).get("spark.dlq_rows_written")),
                        ("Normalisation failures", series_by_name(metrics.data).get("postgres.normalize_failures"))],
                       "records")
        for note in d.get("notes", []):
            st.info(note)
        if d.get("samples"):
            st.markdown("**Newest dead-lettered records** (payloads truncated, labels removed)")
            st.dataframe([{k: s.get(k) for k in ("timestamp", "error", "partition", "offset", "payload_preview")}
                          for s in d["samples"][:25]], width="stretch", hide_index=True)
        if d.get("recent_normalize_failures"):
            st.markdown("**Recent normalisation failures**")
            st.dataframe(d["recent_normalize_failures"], width="stretch", hide_index=True)

# -- Anomalies ----------------------------------------------------------------------
with tabs[3]:
    if metrics.ok:
        m = metrics_by_name(metrics.data)
        cols = st.columns(3)
        metric_tile(cols[0], "Windows scored", m.get("detections.scored_windows"))
        metric_tile(cols[1], "Windows flagged", m.get("detections.flagged_windows"))
        metric_tile(cols[2], "Last score", m.get("detections.seconds_since_last_score"))
        line_chart("Flagged detection windows",
                   [("Flagged", series_by_name(metrics.data).get("detections.flagged"))], "windows")
    detections = fetch("/api/ops/detections", window_minutes=max(window, 60), limit=50)
    if not detections.ok:
        show_error(detections, "Detections")
    else:
        items = dig(detections.data, "items", default=[])
        st.caption(dig(detections.data, "score_semantics", default=""))
        if not items:
            st.info("No flagged detections in the window.")
        else:
            st.dataframe([{k: i.get(k) for k in ("detection_id", "host_name", "window_start", "score",
                                                 "event_count", "model_version")} for i in items],
                         width="stretch", hide_index=True)
            chosen = st.selectbox("Inspect detection", [i["detection_id"] for i in items])
            detail = fetch(f"/api/ops/detections/{chosen}")
            if not detail.ok:
                show_error(detail, "Detection detail")
            else:
                dd = detail.data
                st.json({"signals": dig(dd, "detection", "signals"), "thresholds": dd.get("thresholds")},
                        expanded=False)
                if dd.get("note"):
                    st.info(dd["note"])
                st.dataframe(dd.get("events", []), width="stretch", hide_index=True)
    host = st.text_input("Host timeline", placeholder="host name, e.g. web-01")
    if host:
        timeline = fetch(f"/api/ops/hosts/{quote(host.strip(), safe='')}/timeline", window_minutes=window)
        if not timeline.ok:
            show_error(timeline, "Host timeline")
        else:
            tl = timeline.data
            st.caption(f"{len(tl.get('events', []))} events"
                       f"{' (truncated)' if tl.get('events_truncated') else ''}, "
                       f"{len(tl.get('detections', []))} detections")
            st.dataframe(tl.get("events", []), width="stretch", hide_index=True)

# -- Evidence integrity -----------------------------------------------------------
with tabs[4]:
    ledger = fetch("/api/ops/ledger/status")
    if not ledger.ok:
        show_error(ledger, "Ledger status")
    else:
        lg = ledger.data
        st.subheader(f"Ledger: {status_label(lg.get('status'))}")
        st.write(lg.get("detail", ""))
        freshness(lg.get("generated_at"))
        cols = st.columns(4)

        def show(col: Any, label: str, value: Any) -> None:
            col.metric(label, "—" if value is None else f"{value:,}" if isinstance(value, int) else str(value))

        show(cols[0], "Blocks", lg.get("blocks"))
        show(cols[1], "Unsealed events", lg.get("unsealed_events"))
        show(cols[2], "Head sequence", lg.get("head_sequence"))
        cols[3].metric("Last seal", humanize_age(lg.get("seconds_since_seal")))
        last = lg.get("last_verification")
        if last:
            verdict = "intact ✅" if last.get("intact") else f"FAILED ❌ ({last.get('finding_count')} findings)"
            st.markdown(f"**Latest verification:** {verdict} — {last.get('events_checked'):,} events, "
                        f"{last.get('blocks_checked'):,} blocks, finished "
                        f"{humanize_age(age_seconds(last.get('finished_at')))}")
            if last.get("findings"):
                st.dataframe(last["findings"], width="stretch", hide_index=True)
        else:
            st.info("No verification recorded yet.")
        if lg.get("head_hash"):
            st.code(f"head hash {lg['head_hash']}", language=None)
        for item in lg.get("limitations", []):
            st.caption(f"• {item}")

# -- Investigate ---------------------------------------------------------------------
with tabs[5]:
    status = client().get("/api/ops/investigations")
    provider = dig(status.data, "provider", default={}) if status.ok else {}
    if not status.ok:
        show_error(status, "Investigation service")
    elif not provider.get("enabled"):
        st.warning(f"Investigations unavailable: {provider.get('reason')}")
    else:
        st.caption(f"Provider: {provider.get('provider')} {provider.get('model') or ''}"
                   + ("" if provider.get("uses_llm") else " — deterministic, no language model"))
    incidents = fetch("/api/ops/incidents", window_minutes=window)
    options = incident_options(incidents.data) if incidents.ok else []
    labels = dict(options)
    chosen_incident = st.selectbox("Incident candidate", [None, *labels],
                                   format_func=lambda i: "— free-form question —" if i is None else labels[i])
    if chosen_incident and incidents.ok:
        candidate = next(c for c in incidents.data["candidates"] if c["incident_id"] == chosen_incident)
        with st.expander("Supporting evidence (rule facts)", expanded=True):
            st.dataframe([{"metric": f.get("name"), "value": metric_display(f)[0],
                           "source": f.get("source"), "detail": f.get("detail")}
                          for f in candidate.get("facts", [])], width="stretch", hide_index=True)
    question = st.text_area("Question (optional)", max_chars=1000)
    if st.button("Investigate", disabled=not provider.get("enabled")):
        payload = {"incident_id": chosen_incident, "question": question or None, "window_minutes": window}
        started = client().post("/api/ops/investigate", payload)
        if started.ok:
            st.session_state["job_id"] = started.data["job_id"]
        else:
            show_error(started, "Investigation")

    @st.fragment(run_every=3)
    def job_panel() -> None:
        job_id = st.session_state.get("job_id")
        if not job_id:
            return
        job = client().get(f"/api/ops/investigations/{job_id}")
        if not job.ok:
            show_error(job, "Investigation status")
            return
        j = job.data
        st.markdown(f"**Investigation `{job_id[:8]}`: {j.get('status')}** "
                    f"· {len(j.get('evidence', []))} evidence items")
        if j.get("status") in {"queued", "running"}:
            st.caption("Running in the background; this panel refreshes every 3 s.")
            return
        if j.get("status") == "failed":
            st.error(f"Investigation failed: {j.get('error')}")
            if j.get("evidence"):
                st.markdown("Evidence gathered before the failure:")
                st.dataframe(j["evidence"], width="stretch", hide_index=True)
            return
        r = j.get("report") or {}
        st.markdown(f"### {SEVERITY_ICON.get(str(r.get('severity')), '⚪')} {r.get('summary')}")
        st.caption(f"Severity {r.get('severity')} — {r.get('severity_basis')} · status {r.get('status')} · "
                   f"generated by {dig(r, 'generated_by', 'provider')} {dig(r, 'generated_by', 'model') or ''}")
        st.markdown("#### Observed")
        for o in r.get("observations", []):
            st.markdown(f"- {o.get('claim')}  \n  <small>evidence {', '.join(o.get('evidence_ids', []))} · "
                        f"{', '.join(o.get('sources', []))}</small>", unsafe_allow_html=False)
        st.markdown("#### Hypotheses")
        for c in r.get("potential_causes", []) or [{"hypothesis": "none supported by evidence"}]:
            st.markdown(f"- **[{c.get('confidence', '—')}]** {c.get('hypothesis')} "
                        f"(evidence {', '.join(c.get('supporting_evidence', []))})")
        st.caption(r.get("confidence_semantics", ""))
        if r.get("runbooks"):
            st.markdown("#### Runbooks")
            for rb in r["runbooks"]:
                st.markdown(f"- `{rb.get('source')}` § **{rb.get('section')}** — {rb.get('relevance')}")
        for heading, key in (("Recommended steps", "recommended_steps"),
                             ("Missing information", "missing_information"),
                             ("Limitations", "limitations"), ("Validation notes", "validation_notes")):
            if r.get(key):
                st.markdown(f"#### {heading}")
                for item in r[key]:
                    st.markdown(f"- {item}")
        with st.expander("Evidence retrieved"):
            st.dataframe(r.get("evidence", []), width="stretch", hide_index=True)

    job_panel()
