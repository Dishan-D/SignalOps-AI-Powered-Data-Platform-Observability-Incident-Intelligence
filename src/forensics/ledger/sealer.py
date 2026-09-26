"""Evidence maintenance loop: normalise, then seal, then periodically verify.

Two jobs in one service, in that order, because the order is a dependency and
not a preference.

**Normalise.** The Spark tier appends flat rows to ``evidence.raw_events`` at
streaming speed; ``evidence.normalize_raw_events()`` drains them into the 3NF
model. That function has to be *called* by something — without this loop the
landing table grows without bound and ``evidence.events`` stays empty, which is
exactly what happened the first time the stack was run end to end.

**Seal.** Events are digested the instant they are inserted, but a digest only
becomes *tamper-evident* once it is sealed into a chained block. Between those
two moments an attacker who can write to both ``evidence.events`` and
``ledger.event_digests`` could alter a record and recompute its digest without
detection. This loop keeps that window small and makes its size observable:
every cycle logs ``unsealed_events``, the exact count of records outside the
chain.

Sealing must follow normalisation in the same cycle — there is nothing to seal
until the rows exist.

    python -m forensics.ledger.sealer
"""

from __future__ import annotations

import signal
import sys
import time
import types
from dataclasses import dataclass
from typing import Any

from forensics.common.config import ConfigError, env_bool, env_float, env_int, env_str
from forensics.common.logging import configure_logging, get_logger

SERVICE_NAME = "ledger-sealer"

logger = get_logger(__name__, component="sealer")


@dataclass(frozen=True, slots=True)
class SealerSettings:
    interval_seconds: float
    batch_size: int
    verify_every_cycles: int
    dsn: str
    normalize_enabled: bool
    normalize_batch_size: int

    @classmethod
    def from_env(cls) -> SealerSettings:
        host = env_str("POSTGRES_HOST", "postgres")
        port = env_str("POSTGRES_PORT", "5432")
        database = env_str("POSTGRES_DB", "forensics")
        user = env_str("POSTGRES_USER", "forensics")
        password = env_str("POSTGRES_PASSWORD", "")
        return cls(
            interval_seconds=env_float("LEDGER_SEAL_INTERVAL_SECONDS", 30.0),
            batch_size=env_int("LEDGER_SEAL_BATCH_SIZE", 10_000),
            # Full verification rehashes every event, so it runs on a slower
            # cadence than sealing. 0 disables it.
            verify_every_cycles=env_int("LEDGER_VERIFY_EVERY_CYCLES", 20),
            dsn=env_str(
                "LEDGER_POSTGRES_DSN",
                f"host={host} port={port} dbname={database} user={user} password={password}",
            ),
            # Disable only if a separate service owns the transform; leaving it
            # off with nothing else draining the landing table means the 3NF
            # model never populates.
            normalize_enabled=env_bool("LEDGER_NORMALIZE_ENABLED", True),
            normalize_batch_size=env_int("LEDGER_NORMALIZE_BATCH_SIZE", 10_000),
        )


class GracefulShutdown:
    """Stop between cycles rather than mid-seal."""

    def __init__(self) -> None:
        self.requested = False
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)

    def _handle(self, signum: int, _frame: types.FrameType | None) -> None:
        logger.info("Shutdown signal received", extra={"signal": signal.Signals(signum).name})
        self.requested = True


def normalize_pending(connection: Any, batch_size: int) -> tuple[int, int]:
    """Drain the landing table into the 3NF model. Returns (normalised, failed).

    Loops until a cycle does nothing, so a backlog is cleared rather than
    trickled one batch per interval.
    """
    normalized = failed = 0
    while True:
        with connection.cursor() as cur:
            cur.execute("SELECT * FROM evidence.normalize_raw_events(%s)", (batch_size,))
            row = cur.fetchone()
        done, bad = (int(row[0]), int(row[1])) if row else (0, 0)
        normalized += done
        failed += bad
        if done == 0 and bad == 0:
            return normalized, failed


def seal_pending(connection: Any, batch_size: int) -> tuple[int, int]:
    """Seal everything outstanding. Returns (blocks written, events sealed)."""
    blocks = events = 0
    while True:
        with connection.cursor() as cur:
            cur.execute("SELECT * FROM ledger.seal_block(%s)", (batch_size,))
            rows = cur.fetchall()
        if not rows:
            return blocks, events
        blocks += 1
        events += int(rows[0][2])


def run(settings: SealerSettings) -> int:  # pragma: no cover - needs a database
    import psycopg

    from forensics.ledger import verifier

    shutdown = GracefulShutdown()
    cycles = 0
    exit_code = 0

    try:
        connection = psycopg.connect(settings.dsn, autocommit=True)
    except Exception:
        logger.critical("Cannot connect to PostgreSQL", exc_info=True)
        return 2

    logger.info(
        "Sealer started",
        extra={
            "interval_seconds": settings.interval_seconds,
            "batch_size": settings.batch_size,
            "verify_every_cycles": settings.verify_every_cycles,
        },
    )

    try:
        with connection:
            while not shutdown.requested:
                cycles += 1
                started = time.perf_counter()
                try:
                    normalized = normalize_failed = 0
                    if settings.normalize_enabled:
                        normalized, normalize_failed = normalize_pending(
                            connection, settings.normalize_batch_size
                        )

                    blocks, events = seal_pending(connection, settings.batch_size)
                    with connection.cursor() as cur:
                        cur.execute("SELECT * FROM ledger.chain_status")
                        status = cur.fetchone()

                    logger.info(
                        "Maintenance cycle complete",
                        extra={
                            "cycle": cycles,
                            "normalized": normalized,
                            "normalize_failed": normalize_failed,
                            "blocks_written": blocks,
                            "events_sealed": events,
                            "total_blocks": status[0] if status else None,
                            # The size of the undetectable-edit window, every cycle.
                            "unsealed_events": status[2] if status else None,
                            "head_sequence": status[3] if status else None,
                            "head_hash": (status[4] or "")[:16] if status else None,
                            "seconds": round(time.perf_counter() - started, 3),
                        },
                    )

                    if (
                        settings.verify_every_cycles
                        and cycles % settings.verify_every_cycles == 0
                    ):
                        report = verifier.verify(connection)
                        if not report.intact:
                            # Loud and non-zero: evidence integrity is the one
                            # failure this system exists to surface.
                            logger.critical(
                                "LEDGER INTEGRITY FAILURE",
                                extra={
                                    "findings": [str(f) for f in report.findings[:20]],
                                    "finding_count": len(report.findings),
                                },
                            )
                            exit_code = 1

                except Exception:
                    # One bad cycle must not stop the loop: both the landing
                    # backlog and the unsealed window would then grow without
                    # bound, and unnoticed.
                    logger.error("Maintenance cycle failed", exc_info=True)

                # Sleep in short slices so SIGTERM is honoured promptly.
                deadline = time.monotonic() + settings.interval_seconds
                while not shutdown.requested and time.monotonic() < deadline:
                    time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
    finally:
        logger.info("Sealer stopped", extra={"cycles": cycles})

    return exit_code


def main() -> int:  # pragma: no cover - needs a database
    try:
        settings = SealerSettings.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    configure_logging(
        service=env_str("SERVICE_NAME", SERVICE_NAME),
        environment=env_str("APP_ENV", "local"),
        level=env_str("LOG_LEVEL", "INFO").upper(),
    )
    return run(settings)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["SealerSettings", "main", "normalize_pending", "run", "seal_pending"]
