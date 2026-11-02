"""Read-only PostgreSQL access for the operational layer.

Every session is opened with ``default_transaction_read_only=on`` and a
``statement_timeout``, so the API cannot write to the evidence store even if a
query were wrong, and a slow query cannot pin a connection. Queries are always
parameterised; callers pass SQL text that is a module constant, never built
from request input.
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Sequence
from typing import Any, Protocol

from forensics.common.logging import get_logger
from signalops.sources.errors import DataSourceError

logger = get_logger(__name__, component="signalops-db")

SOURCE = "postgres"


class Database(Protocol):
    def fetch_all(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[dict[str, Any]]: ...

    def fetch_one(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> dict[str, Any] | None: ...

    def ping(self) -> None: ...


class PostgresDatabase:
    """A small fixed-size connection pool over psycopg 3."""

    def __init__(
        self,
        dsn: str,
        *,
        connect_timeout_seconds: int = 3,
        statement_timeout_ms: int = 5_000,
        pool_size: int = 4,
    ) -> None:
        self._dsn = dsn
        self._connect_timeout = connect_timeout_seconds
        self._statement_timeout_ms = statement_timeout_ms
        self._pool: queue.LifoQueue[Any] = queue.LifoQueue(maxsize=pool_size)
        self._slots = threading.BoundedSemaphore(pool_size)

    def _connect(self) -> Any:
        import psycopg
        from psycopg.rows import dict_row

        try:
            return psycopg.connect(
                self._dsn,
                autocommit=True,
                connect_timeout=self._connect_timeout,
                row_factory=dict_row,
                options=(
                    f"-c statement_timeout={self._statement_timeout_ms} "
                    "-c default_transaction_read_only=on "
                    "-c application_name=signalops"
                ),
            )
        except psycopg.Error as exc:
            raise DataSourceError(SOURCE, f"cannot connect: {exc.__class__.__name__}",
                                  unavailable=True) from exc

    def _run(self, sql: str, params: Sequence[Any] | dict[str, Any], *, one: bool) -> Any:
        import psycopg

        if not self._slots.acquire(timeout=self._connect_timeout + 2):
            raise DataSourceError(SOURCE, "connection pool exhausted", unavailable=True)
        connection = None
        try:
            try:
                connection = self._pool.get_nowait()
            except queue.Empty:
                connection = self._connect()
            try:
                with connection.cursor() as cur:
                    cur.execute(sql, params)
                    result = cur.fetchone() if one else cur.fetchall()
            except psycopg.OperationalError as exc:
                connection.close()
                connection = None
                raise DataSourceError(SOURCE, f"connection lost: {exc.__class__.__name__}",
                                      unavailable=True) from exc
            except psycopg.errors.UndefinedTable as exc:
                raise DataSourceError(
                    SOURCE,
                    "relation missing — are migrations (incl. 0005_ops_telemetry) applied?",
                    unavailable=False,
                ) from exc
            except psycopg.errors.QueryCanceled as exc:
                raise DataSourceError(SOURCE, "statement timeout", unavailable=False) from exc
            except psycopg.Error as exc:
                raise DataSourceError(SOURCE, f"query failed: {exc.__class__.__name__}",
                                      unavailable=False) from exc
            return result
        finally:
            if connection is not None and not connection.closed:
                try:
                    self._pool.put_nowait(connection)
                except queue.Full:
                    connection.close()
            self._slots.release()

    def fetch_all(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[dict[str, Any]]:
        return list(self._run(sql, params, one=False))

    def fetch_one(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> dict[str, Any] | None:
        result = self._run(sql, params, one=True)
        return dict(result) if result is not None else None

    def ping(self) -> None:
        self._run("SELECT 1 AS ok", (), one=True)

    def close(self) -> None:
        while True:
            try:
                self._pool.get_nowait().close()
            except queue.Empty:
                return
