"""The one exception type data sources raise."""

from __future__ import annotations


class DataSourceError(RuntimeError):
    """A source could not answer.

    ``unavailable`` distinguishes "could not reach it" (connection refused,
    timeout on connect) from "reached it and the query failed" — the two map to
    different health states and must not be collapsed.
    """

    def __init__(self, source: str, message: str, *, unavailable: bool) -> None:
        super().__init__(f"{source}: {message}")
        self.source = source
        self.message = message
        self.unavailable = unavailable
