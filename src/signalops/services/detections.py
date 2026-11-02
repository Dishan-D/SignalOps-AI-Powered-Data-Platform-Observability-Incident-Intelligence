"""Detections, detection evidence and host timelines.

Reads ``analytics.detections`` (written by the scorer) and the normalised
``evidence.events`` model. Never touches ``analytics.event_labels``,
``analytics.detection_truth`` or the ``eval_*`` landing columns: ground truth is
for offline evaluation only, and exposing it here would leak it into operator
judgement and the agent's context.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

from signalops.models import (
    Detection,
    DetectionDetail,
    DetectionPage,
    HostTimeline,
    TimelineEvent,
    utcnow,
)
from signalops.services.common import MAX_LIMIT, clamp_window
from signalops.sources.postgres import Database

HOST_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
MAX_TIMELINE_EVENTS = 500
MAX_DETAIL_EVENTS = 200


class NotFoundError(LookupError):
    """The requested record does not exist."""


def validate_host_name(host_name: str) -> str:
    if not HOST_NAME_PATTERN.fullmatch(host_name or ""):
        raise ValueError("host name must be 1-253 characters of letters, digits, '.', '_' or '-'")
    return host_name


_DETECTION_COLUMNS = """
       d.detection_id, d.host_name, d.window_start, d.window_end, d.scored_at,
       d.score, d.flagged, d.signals, r.model_version,
       cardinality(d.event_ids) AS event_count
"""

LIST_SQL = f"""
SELECT {_DETECTION_COLUMNS}
  FROM analytics.detections d
  LEFT JOIN analytics.model_runs r ON r.run_id = d.run_id
 WHERE d.window_start >= now() - make_interval(mins => %(window)s)
   AND (NOT %(flagged_only)s OR d.flagged)
   AND (%(host)s::text IS NULL OR d.host_name = %(host)s::text)
 ORDER BY d.window_start DESC, d.detection_id DESC
 LIMIT %(limit)s OFFSET %(offset)s
"""

COUNT_SQL = """
SELECT count(*) AS n
  FROM analytics.detections d
 WHERE d.window_start >= now() - make_interval(mins => %(window)s)
   AND (NOT %(flagged_only)s OR d.flagged)
   AND (%(host)s::text IS NULL OR d.host_name = %(host)s::text)
"""

DETAIL_SQL = f"""
SELECT {_DETECTION_COLUMNS}, r.thresholds,
       (d.event_ids)[1:%(max_events)s]::text[] AS event_ids
  FROM analytics.detections d
  LEFT JOIN analytics.model_runs r ON r.run_id = d.run_id
 WHERE d.detection_id = %(detection_id)s
"""

_EVENT_COLUMNS = """
       e.event_id::text AS event_id, e.occurred_at, e.category::text AS category, e.action,
       e.outcome::text AS outcome, e.severity, left(e.message, 500) AS message,
       u.user_name, pi.name AS process_name,
       left(e.process_command_line, 300) AS command_line,
       host(sa.address) AS source_ip, host(da.address) AS destination_ip, e.destination_port
"""

_EVENT_JOINS = """
  LEFT JOIN evidence.users u ON u.user_id = e.user_id
  LEFT JOIN evidence.process_images pi ON pi.image_id = e.process_image_id
  LEFT JOIN evidence.network_addresses sa ON sa.address_id = e.source_address_id
  LEFT JOIN evidence.network_addresses da ON da.address_id = e.destination_address_id
"""

EVENTS_BY_ID_SQL = f"""
SELECT {_EVENT_COLUMNS}
  FROM evidence.events e {_EVENT_JOINS}
 WHERE e.event_id = ANY(%(ids)s::uuid[])
   AND e.occurred_at BETWEEN %(start)s::timestamptz - interval '1 hour'
                         AND %(end)s::timestamptz + interval '1 hour'
 ORDER BY e.occurred_at
 LIMIT %(limit)s
"""

HOST_SQL = "SELECT host_id FROM evidence.hosts WHERE host_name = %(host)s"

HOST_EVENTS_SQL = f"""
SELECT {_EVENT_COLUMNS}
  FROM evidence.events e {_EVENT_JOINS}
 WHERE e.host_id = %(host_id)s
   AND e.occurred_at >= %(start)s AND e.occurred_at <= %(end)s
 ORDER BY e.occurred_at DESC
 LIMIT %(limit)s
"""

HOST_DETECTIONS_SQL = f"""
SELECT {_DETECTION_COLUMNS}
  FROM analytics.detections d
  LEFT JOIN analytics.model_runs r ON r.run_id = d.run_id
 WHERE d.host_name = %(host)s
   AND d.window_start >= %(start)s AND d.window_start <= %(end)s
 ORDER BY d.window_start DESC
 LIMIT %(limit)s
"""

HOST_DETECTION_EXISTS_SQL = "SELECT 1 AS ok FROM analytics.detections WHERE host_name = %(host)s LIMIT 1"


def _detection(row: dict[str, Any]) -> Detection:
    signals = row.get("signals") or {}
    return Detection(
        detection_id=int(row["detection_id"]), host_name=row["host_name"],
        window_start=row["window_start"], window_end=row["window_end"],
        scored_at=row["scored_at"], score=float(row["score"]), flagged=bool(row["flagged"]),
        signals={str(k): float(v) for k, v in signals.items() if isinstance(v, (int, float))},
        model_version=row.get("model_version"), event_count=int(row.get("event_count") or 0),
    )


class DetectionService:
    def __init__(self, db: Database) -> None:
        self._db = db

    def list(self, *, window_minutes: int = 1440, flagged_only: bool = True,
             host_name: str | None = None, limit: int = 50, offset: int = 0) -> DetectionPage:
        window = clamp_window(window_minutes)
        if not 1 <= limit <= MAX_LIMIT:
            raise ValueError(f"limit must be within 1..{MAX_LIMIT}")
        if not 0 <= offset <= 100_000:
            raise ValueError("offset must be within 0..100000")
        host = validate_host_name(host_name) if host_name else None
        params = {"window": window, "flagged_only": flagged_only, "host": host,
                  "limit": limit, "offset": offset}
        rows = self._db.fetch_all(LIST_SQL, params)
        total = (self._db.fetch_one(COUNT_SQL, params) or {}).get("n", 0)
        return DetectionPage(generated_at=utcnow(), window_minutes=window,
                             flagged_only=flagged_only, limit=limit, offset=offset,
                             total=int(total), items=[_detection(r) for r in rows])

    def detail(self, detection_id: int, *, max_events: int = 50) -> DetectionDetail:
        if detection_id < 1:
            raise ValueError("detection_id must be positive")
        max_events = max(1, min(max_events, MAX_DETAIL_EVENTS))
        row = self._db.fetch_one(DETAIL_SQL, {"detection_id": detection_id,
                                              "max_events": max_events})
        if row is None:
            raise NotFoundError(f"detection {detection_id} not found")
        detection = _detection(row)
        ids = [i for i in (row.get("event_ids") or []) if i]
        events: list[TimelineEvent] = []
        if ids:
            events = [TimelineEvent(**r) for r in self._db.fetch_all(EVENTS_BY_ID_SQL, {
                "ids": ids, "start": detection.window_start, "end": detection.window_end,
                "limit": max_events,
            })]
        note = None
        if len(events) < len(ids):
            note = (f"{len(ids) - len(events)} of {len(ids)} referenced events are not (yet) in "
                    "evidence.events — they may still be awaiting normalisation.")
        thresholds = row.get("thresholds")
        return DetectionDetail(
            detection=detection,
            thresholds={k: float(v) for k, v in thresholds.items()} if isinstance(thresholds, dict) else None,
            events=events, events_requested=len(ids), events_found=len(events), note=note,
        )

    def host_timeline(self, host_name: str, *, window_minutes: int = 60,
                      end: dt.datetime | None = None, limit: int = 200) -> HostTimeline:
        host = validate_host_name(host_name)
        window = clamp_window(window_minutes)
        limit = max(1, min(limit, MAX_TIMELINE_EVENTS))
        end = end or utcnow()
        start = end - dt.timedelta(minutes=window)
        host_row = self._db.fetch_one(HOST_SQL, {"host": host})
        events: list[TimelineEvent] = []
        truncated = False
        if host_row is not None:
            rows = self._db.fetch_all(HOST_EVENTS_SQL, {
                "host_id": host_row["host_id"], "start": start, "end": end, "limit": limit + 1})
            truncated = len(rows) > limit
            events = [TimelineEvent(**r) for r in rows[:limit]]
        detections = [_detection(r) for r in self._db.fetch_all(
            HOST_DETECTIONS_SQL, {"host": host, "start": start, "end": end, "limit": 100})]
        if host_row is None and not detections and self._db.fetch_one(
                HOST_DETECTION_EXISTS_SQL, {"host": host}) is None:
            raise NotFoundError(f"host {host!r} has no evidence or detections")
        return HostTimeline(host_name=host, known_host=host_row is not None, window_start=start,
                            window_end=end, events=events, events_truncated=truncated,
                            detections=detections)
