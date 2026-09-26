"""Turn normalised events into per-host log-key sequences.

An individual log line is rarely anomalous on its own — ``Failed password`` is
ordinary. What is anomalous is *thirty of them followed by a success*, or an
``execve`` of ``nc`` immediately followed by an outbound connection. The unit of
detection is therefore a short **sequence** of log keys from one host, in time
order, and the model's job is to learn which continuations are normal.

Sequences are built per host for the same reason the Kafka topic is keyed by
host: interleaving two machines' logs into one sequence would manufacture
transitions that never happened.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field

from forensics.inference.templates import DrainTemplateMiner
from forensics.inference.vocabulary import PAD_ID, LogKey, LogKeyVocabulary

#: Default window. Long enough to contain a short attack chain (exec then
#: connect), short enough that one burst does not dominate a sequence.
DEFAULT_WINDOW_SIZE = 16

#: Step between consecutive windows. A stride below the window size overlaps
#: them, so an attack chain straddling a boundary is still seen intact by at
#: least one window — the same reason the Spark feature windows slide.
DEFAULT_STRIDE = 4


@dataclass(slots=True)
class EventRecord:
    """The minimum a sequence needs. Decouples this tier from the wire schema."""

    event_id: str
    host_name: str
    timestamp: dt.datetime
    message: str
    outcome: str
    # Evaluation only — never reaches a tensor. See `label_window`.
    is_anomaly: bool = False
    scenario: str | None = None


@dataclass(slots=True)
class SequenceWindow:
    """One training/inference example."""

    host_name: str
    token_ids: list[int]
    start_time: dt.datetime
    end_time: dt.datetime
    event_ids: list[str] = field(default_factory=list)
    # Ground truth for evaluation. Held alongside, never fed to the model.
    is_anomaly: bool = False
    scenarios: tuple[str, ...] = ()

    # No __len__: it would make a window's truthiness depend on a mutable
    # field, so `if window:` would silently skip an unencoded one. Callers use
    # `is not None`, and `len(window.token_ids)` when they want the length.


class SequenceBuilder:
    """Builds log-key sequences, owning the miner and the vocabulary together.

    They are paired deliberately: a template id means nothing without the miner
    that produced it, and a token id means nothing without the vocabulary. They
    are fitted together and frozen together.
    """

    def __init__(
        self,
        *,
        miner: DrainTemplateMiner | None = None,
        vocabulary: LogKeyVocabulary | None = None,
        window_size: int = DEFAULT_WINDOW_SIZE,
        stride: int = DEFAULT_STRIDE,
    ) -> None:
        if window_size < 2:
            raise ValueError("window_size must be at least 2")
        if not 1 <= stride <= window_size:
            raise ValueError("stride must be between 1 and window_size")
        self.miner = miner or DrainTemplateMiner()
        self.vocabulary = vocabulary or LogKeyVocabulary()
        self.window_size = window_size
        self.stride = stride

    # -- key extraction -------------------------------------------------------

    def _token_for(self, record: EventRecord, *, learn: bool) -> int:
        """Map one event to a token id."""
        if learn:
            match = self.miner.add(record.message)
        else:
            found = self.miner.match(record.message)
            if found is None:
                # Unknown template: the vocabulary cannot represent it.
                from forensics.inference.vocabulary import UNK_ID

                return UNK_ID
            match = found

        key = LogKey(template_id=match.cluster_id, outcome=record.outcome or "unknown")
        return self.vocabulary.add(key) if learn else self.vocabulary.lookup(key)

    # -- windowing ------------------------------------------------------------

    def _windows_for_host(
        self, host: str, records: list[EventRecord], *, learn: bool
    ) -> Iterator[SequenceWindow]:
        tokens = [self._token_for(r, learn=learn) for r in records]

        # A host with fewer events than one window still deserves a sequence;
        # dropping it would blind the detector to low-volume machines, which is
        # where a quiet compromise hides.
        if len(records) < self.window_size:
            spans = [(0, len(records))]
        else:
            spans = [
                (start, start + self.window_size)
                for start in range(0, len(records) - self.window_size + 1, self.stride)
            ]

        for start, end in spans:
            chunk = records[start:end]
            window_tokens = tokens[start:end]
            # Right-pad so every example is the same length; PAD_ID is masked
            # out of both attention and loss.
            if len(window_tokens) < self.window_size:
                window_tokens = window_tokens + [PAD_ID] * (
                    self.window_size - len(window_tokens)
                )
            scenarios = tuple(
                sorted({r.scenario for r in chunk if r.scenario is not None})
            )
            yield SequenceWindow(
                host_name=host,
                token_ids=window_tokens,
                start_time=chunk[0].timestamp,
                end_time=chunk[-1].timestamp,
                event_ids=[r.event_id for r in chunk],
                # A window is anomalous if it contains any attack event: the
                # detector is asked "is something wrong in this span?", not
                # "is every line here malicious?".
                is_anomaly=any(r.is_anomaly for r in chunk),
                scenarios=scenarios,
            )

    def build(
        self, records: Iterable[EventRecord], *, learn: bool = False
    ) -> list[SequenceWindow]:
        """Group by host, order by time, and emit sliding windows.

        ``learn=True`` grows the miner and vocabulary (training). At inference
        both must be frozen, or token ids drift out from under the embeddings.
        """
        by_host: dict[str, list[EventRecord]] = {}
        for record in records:
            by_host.setdefault(record.host_name, []).append(record)

        windows: list[SequenceWindow] = []
        for host, host_records in sorted(by_host.items()):
            # Stable sort on time; ties keep arrival order, which for one host
            # on one partition is the true order.
            host_records.sort(key=lambda r: r.timestamp)
            windows.extend(self._windows_for_host(host, host_records, learn=learn))
        return windows

    def fit(self, records: Iterable[EventRecord]) -> list[SequenceWindow]:
        """Learn templates and vocabulary, then freeze both."""
        windows = self.build(records, learn=True)
        self.vocabulary.freeze()
        return windows

    def transform(self, records: Iterable[EventRecord]) -> list[SequenceWindow]:
        return self.build(records, learn=False)


def to_records(events: Sequence, *, include_labels: bool = True) -> list[EventRecord]:
    """Adapt generated :class:`LogEvent` objects into :class:`EventRecord`.

    Used by training and evaluation. The Kafka consumer builds ``EventRecord``
    straight from the normalised JSON instead.
    """
    records: list[EventRecord] = []
    for event in events:
        truth = event.labels.get("ground_truth") or {}
        records.append(
            EventRecord(
                event_id=event.event_id,
                host_name=event.host.name,
                timestamp=dt.datetime.fromisoformat(event.timestamp),
                message=event.message,
                outcome=str(event.outcome),
                is_anomaly=bool(truth.get("is_anomaly")) if include_labels else False,
                scenario=truth.get("scenario") if include_labels else None,
            )
        )
    return records
