"""Log-key vocabulary: the token alphabet the sequence model consumes.

A *log key* is not simply a Drain template id here. It is the pair

    (template_id, outcome)

mapped to a dense integer.

**Why the composite.** Drain's similarity is position-wise and blind to which
token carries meaning. The first time it sees

    sshd[4021]: Failed   password for a.sharma from 203.0.113.9 port 44312 ssh2
    sshd[9117]: Accepted password for j.okafor from 198.51.100.7 port 51221 ssh2

they differ in one token out of eleven — similarity ~0.9 — so they merge into
``sshd[<NUM>]: <*> password for <*> from <IP> port <NUM> ssh2``. The merge is
sticky: once ``Failed`` has been generalised to ``<*>`` every later message
matches, and raising the threshold high enough to prevent it (>0.9) shatters
every other template. Measured at thresholds 0.5, 0.6 and 0.7 — the merge
survives all three.

That merge erases exactly the distinction a brute-force detector needs. But the
pipeline is not limited to raw text: normalisation already produced a structured
``outcome`` field. Folding it into the key restores the signal without fighting
the parser, and costs one extra dimension of vocabulary.

Reserved ids occupy the low indices so a tensor of zeros is valid padding.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Padding for short sequences. Must be 0 so zero-initialised tensors are valid.
PAD_ID = 0
#: A log key unseen during training. Its presence is itself weak evidence of
#: novelty, but it is deliberately *not* treated as an automatic anomaly —
#: template drift after a package upgrade would otherwise fire constantly.
UNK_ID = 1
#: Masked position for the MLM training objective.
MASK_ID = 2

RESERVED_IDS = (PAD_ID, UNK_ID, MASK_ID)
FIRST_FREE_ID = 3


@dataclass(frozen=True, slots=True)
class LogKey:
    """The natural key of a log type."""

    template_id: int
    outcome: str

    def __str__(self) -> str:
        return f"E{self.template_id}/{self.outcome}"


class LogKeyVocabulary:
    """Bidirectional map between :class:`LogKey` and dense token ids.

    Frozen after training. Ids are the model's input alphabet, so a vocabulary
    that kept growing at inference time would silently change what every
    embedding means.
    """

    def __init__(self) -> None:
        self._to_id: dict[LogKey, int] = {}
        self._to_key: dict[int, LogKey] = {}
        self._counts: dict[int, int] = {}
        self._next_id = FIRST_FREE_ID
        self._frozen = False

    def add(self, key: LogKey) -> int:
        """Return the id for ``key``, assigning one if new (unless frozen)."""
        existing = self._to_id.get(key)
        if existing is not None:
            self._counts[existing] = self._counts.get(existing, 0) + 1
            return existing
        if self._frozen:
            return UNK_ID

        token_id = self._next_id
        self._next_id += 1
        self._to_id[key] = token_id
        self._to_key[token_id] = key
        self._counts[token_id] = 1
        return token_id

    def lookup(self, key: LogKey) -> int:
        """Id for ``key``, or ``UNK_ID`` — never mutates."""
        return self._to_id.get(key, UNK_ID)

    def key_for(self, token_id: int) -> LogKey | None:
        return self._to_key.get(token_id)

    def freeze(self) -> LogKeyVocabulary:
        self._frozen = True
        return self

    @property
    def frozen(self) -> bool:
        return self._frozen

    @property
    def size(self) -> int:
        """Total embedding rows required, reserved ids included."""
        return self._next_id

    def counts(self) -> dict[int, int]:
        return dict(self._counts)

    def to_dict(self) -> dict[str, object]:
        return {
            "next_id": self._next_id,
            "frozen": self._frozen,
            "entries": [
                {
                    "template_id": key.template_id,
                    "outcome": key.outcome,
                    "token_id": token_id,
                    "count": self._counts.get(token_id, 0),
                }
                for key, token_id in self._to_id.items()
            ],
        }

    @classmethod
    def from_dict(cls, state: dict) -> LogKeyVocabulary:
        vocab = cls()
        for entry in state["entries"]:
            key = LogKey(int(entry["template_id"]), str(entry["outcome"]))
            token_id = int(entry["token_id"])
            vocab._to_id[key] = token_id
            vocab._to_key[token_id] = key
            vocab._counts[token_id] = int(entry.get("count", 0))
        vocab._next_id = int(state["next_id"])
        vocab._frozen = bool(state["frozen"])
        return vocab
