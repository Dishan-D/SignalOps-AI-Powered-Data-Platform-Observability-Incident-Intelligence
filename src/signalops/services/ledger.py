"""Evidence-ledger status.

Sealing state comes from ``ledger.chain_status`` (migration 0004). Integrity
comes from the *out-of-database* verifier (``forensics.ledger.verifier``) as run
by the sealer, whose outcomes are persisted to ``ops.ledger_verifications``.

The API deliberately does not run a verification itself: a full pass rehashes
every event, which is far too slow for a request path and would let anyone with
API access load the database at will. ``scripts/verify_ledger.py`` remains the
on-demand route.
"""

from __future__ import annotations

from typing import Any

from signalops.config import Thresholds
from signalops.models import (
    LedgerFinding,
    LedgerStatus,
    LedgerVerification,
    Status,
    utcnow,
)
from signalops.services.common import seconds_since
from signalops.sources.errors import DataSourceError
from signalops.sources.postgres import Database

CHAIN_STATUS_SQL = "SELECT * FROM ledger.chain_status"

VERIFICATIONS_SQL = """
SELECT verification_id, started_at, finished_at, intact, events_checked, blocks_checked,
       unsealed_events, finding_count, findings
  FROM ops.ledger_verifications
 ORDER BY finished_at DESC
 LIMIT 1
"""

RECENT_FAILURES_SQL = """
SELECT verification_id, started_at, finished_at, intact, events_checked, blocks_checked,
       unsealed_events, finding_count, findings
  FROM ops.ledger_verifications
 WHERE NOT intact
 ORDER BY finished_at DESC
 LIMIT %(limit)s
"""

LIMITATIONS = [
    "Events between insert and the next seal are digested but not yet chained; a coordinated "
    "edit to an event and its digest in that window is not detectable (see unsealed_events).",
    "Integrity status reflects the most recent full verification run by the sealer, not a live "
    "check. Run scripts/verify_ledger.py for an on-demand verification.",
    "The ledger proves records were not modified after sealing; it does not prove a record was "
    "true when it was written.",
]


def _verification(row: dict[str, Any]) -> LedgerVerification:
    findings = row.get("findings") or []
    return LedgerVerification(
        verification_id=row["verification_id"], started_at=row["started_at"],
        finished_at=row["finished_at"], intact=row["intact"],
        events_checked=row["events_checked"], blocks_checked=row["blocks_checked"],
        unsealed_events=row["unsealed_events"], finding_count=row["finding_count"],
        findings=[LedgerFinding(**f) for f in findings[:20] if isinstance(f, dict)],
    )


class LedgerService:
    def __init__(self, db: Database, thresholds: Thresholds) -> None:
        self._db = db
        self._thresholds = thresholds

    def status(self) -> LedgerStatus:
        now = utcnow()
        try:
            chain = self._db.fetch_one(CHAIN_STATUS_SQL) or {}
        except DataSourceError as exc:
            return LedgerStatus(
                generated_at=now,
                status=Status.unavailable if exc.unavailable else Status.unknown,
                detail=f"ledger.chain_status unreadable: {exc.message}",
                limitations=LIMITATIONS,
            )

        seal_age = seconds_since(chain.get("last_sealed_at"), now)
        unsealed = chain.get("unsealed_events")
        status = LedgerStatus(
            generated_at=now, status=Status.unknown, detail="",
            blocks=chain.get("blocks"), digested_events=chain.get("digested_events"),
            unsealed_events=unsealed, head_sequence=chain.get("head_sequence"),
            head_hash=chain.get("head_hash"), last_sealed_at=chain.get("last_sealed_at"),
            seconds_since_seal=seal_age, limitations=LIMITATIONS,
        )

        verification_error = None
        try:
            latest = self._db.fetch_one(VERIFICATIONS_SQL)
            status.last_verification = _verification(latest) if latest else None
            status.recent_failures = [
                _verification(r) for r in self._db.fetch_all(RECENT_FAILURES_SQL, {"limit": 5})]
        except DataSourceError as exc:
            verification_error = exc.message

        problems: list[str] = []
        verdict = Status.healthy
        last = status.last_verification
        if verification_error:
            verdict = Status.unknown
            problems.append(f"verification history unreadable: {verification_error}")
        elif last is None:
            verdict = Status.unknown
            problems.append("no ledger verification has been recorded yet")
        elif not last.intact:
            verdict = Status.unhealthy
            problems.append(f"latest verification found {last.finding_count} integrity finding(s)")
        else:
            age = seconds_since(last.finished_at, now) or 0.0
            if age > self._thresholds.verification_stale_seconds:
                verdict = Status.degraded
                problems.append(f"latest verification is {int(age)}s old")

        if unsealed and (seal_age is None or seal_age > self._thresholds.seal_stale_seconds):
            if verdict in (Status.healthy, Status.unknown):
                verdict = Status.degraded
            problems.append(
                f"{unsealed} events unsealed and "
                + ("no block has ever been sealed" if seal_age is None
                   else f"last seal was {int(seal_age)}s ago")
            )

        status.status = verdict
        status.detail = "; ".join(problems) if problems else (
            f"chain intact at last verification; {unsealed or 0} events awaiting the next seal")
        return status
