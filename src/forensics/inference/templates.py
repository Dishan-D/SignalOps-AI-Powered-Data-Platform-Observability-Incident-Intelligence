"""Log template mining (Drain).

Turns an unbounded stream of raw log lines into a small, stable vocabulary of
*log keys* — the token alphabet the sequence model in :mod:`.model` consumes.

    sshd[4021]: Failed password for a.sharma from 203.0.113.9 port 44312 ssh2
    sshd[9117]: Failed password for j.okafor from 198.51.100.7 port 51221 ssh2
                                  |
                                  v
    E7: "sshd[<NUM>]: Failed password for <*> from <IP> port <NUM> ssh2"

Drain is a fixed-depth parse tree: messages are bucketed by token count, then by
their leading tokens, and only compared against the handful of clusters sharing
that prefix. That keeps matching O(depth) instead of O(clusters), which is what
makes it viable in a streaming path.

Implemented here rather than pulled from the ``drain3`` package for two reasons:
the state model (template id assignment, persistence to Postgres, stability of
ids across restarts) is something this pipeline needs to own, and it removes a
dependency from the inference container. The algorithm is He et al. (2017).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

#: Wildcard marking a token position that varies between messages of one type.
WILDCARD = "<*>"

#: Pre-masking patterns, applied in order. These collapse token classes whose
#: cardinality is effectively unbounded — without them every distinct IP or PID
#: spawns its own cluster and the vocabulary never converges.
#:
#: Usernames and executable paths are deliberately NOT masked: Drain discovers
#: those variable positions on its own, and over-masking would erase the
#: distinction between `/bin/bash` and `/bin/nc`, which is exactly the signal
#: the detector needs.
_MASK_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # IPv4, optionally with a port suffix handled separately by the NUM rule.
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"), "<UUID>"),
    # Long hex runs: key fingerprints, hashes, random filename stems.
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "<HEX>"),
    (re.compile(r"\b\d+\b"), "<NUM>"),
)

_TOKEN_SPLIT = re.compile(r"[\s=,]+")


def preprocess(message: str) -> str:
    """Apply the masking rules to a raw log line."""
    for pattern, replacement in _MASK_PATTERNS:
        message = pattern.sub(replacement, message)
    return message


def tokenize(message: str) -> list[str]:
    """Split a masked message into comparison tokens."""
    return [t for t in _TOKEN_SPLIT.split(message.strip()) if t]


def _has_variable_marker(token: str) -> bool:
    """True for tokens already known to vary (masked or wildcard)."""
    return token.startswith("<") and token.endswith(">")


@dataclass(slots=True)
class LogCluster:
    """One discovered log type."""

    cluster_id: int
    tokens: list[str]
    count: int = 0

    @property
    def template(self) -> str:
        return " ".join(self.tokens)

    def similarity(self, tokens: list[str]) -> float:
        """Fraction of positions that agree.

        Wildcard positions score 0 rather than 1 deliberately: counting them as
        matches makes an already-general template look like a great fit for
        everything, and the cluster degenerates into a single all-wildcard
        catch-all that carries no information.
        """
        if len(tokens) != len(self.tokens):
            return 0.0
        if not tokens:
            return 1.0
        matches = sum(
            1
            for mine, theirs in zip(self.tokens, tokens, strict=True)
            if mine == theirs and mine != WILDCARD
        )
        return matches / len(tokens)

    def merge(self, tokens: list[str]) -> bool:
        """Generalise the template against a newly matched message.

        Returns True when the template actually changed, so callers can persist
        only real updates.
        """
        changed = False
        for index, token in enumerate(tokens):
            if self.tokens[index] != token and self.tokens[index] != WILDCARD:
                self.tokens[index] = WILDCARD
                changed = True
        self.count += 1
        return changed


@dataclass(slots=True)
class _Node:
    """Internal parse-tree node: children keyed by token, leaves hold clusters."""

    children: dict[str, _Node] = field(default_factory=dict)
    clusters: list[LogCluster] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class MatchResult:
    cluster_id: int
    template: str
    created: bool  # a new log type was seen for the first time
    updated: bool  # an existing template was generalised


class DrainTemplateMiner:
    """Fixed-depth parse tree over log messages.

    Parameters mirror the paper's:

    * ``depth`` — how many leading tokens are used for tree descent. Deeper
      means narrower buckets and fewer comparisons, but a message whose
      variable part appears early gets scattered across many leaves.
    * ``similarity_threshold`` — how close a message must be to join a cluster.
      Too low and unrelated messages collapse into one all-wildcard template;
      too high and the vocabulary grows without bound.
    * ``max_children`` — fan-out cap per node. Beyond it, messages fall into a
      shared ``<*>`` branch so a high-cardinality token cannot explode the tree.

    **Why depth defaults to 3, not the paper's 4.** Measured on 20 000 generated
    messages, then evaluated on a held-out stream with entirely different users
    and hosts:

    ==========  =========  ===============  ===================
    depth       templates  sudo templates   unmatched (held-out)
    ==========  =========  ===============  ===================
    3               14           1                 0.0%
    4               27          13                 0.4%
    ==========  =========  ===============  ===================

    ``sudo: <user> : N incorrect password attempts`` puts the username in the
    second token. At depth 4 that token is a tree branch, so every user gets a
    private subtree and one log type shatters into 13 template ids — and a user
    unseen during training produces an *unknown* token at inference, making
    ordinary activity look novel. Depth 3 branches on the daemon name only and
    lets similarity matching generalise the username position to ``<*>``.
    """

    def __init__(
        self,
        *,
        depth: int = 3,
        similarity_threshold: float = 0.5,
        max_children: int = 100,
    ) -> None:
        if depth < 2:
            raise ValueError("depth must be at least 2 (length node + one token node)")
        # The paper counts the length node and the leaf within the depth.
        self._max_token_depth = depth - 2
        self._threshold = similarity_threshold
        self._max_children = max_children
        self._root = _Node()
        self._clusters: dict[int, LogCluster] = {}
        self._next_id = 1

    # -- tree navigation ------------------------------------------------------

    def _descend(self, tokens: list[str], *, create: bool) -> _Node | None:
        """Walk to the leaf node for ``tokens``, optionally creating the path."""
        node = self._root
        length_key = str(len(tokens))

        child = node.children.get(length_key)
        if child is None:
            if not create:
                return None
            child = node.children[length_key] = _Node()
        node = child

        for token in tokens[: self._max_token_depth]:
            # A token that already contains a variable marker must not become a
            # tree branch, or every distinct value spawns a subtree.
            key = WILDCARD if _has_variable_marker(token) else token

            child = node.children.get(key)
            if child is None:
                if not create:
                    # Fall back to the wildcard branch if one exists.
                    child = node.children.get(WILDCARD)
                    if child is None:
                        return None
                elif len(node.children) >= self._max_children:
                    # Fan-out cap reached: share the wildcard branch.
                    child = node.children.setdefault(WILDCARD, _Node())
                else:
                    child = node.children[key] = _Node()
            node = child

        return node

    # -- public API -----------------------------------------------------------

    def add(self, message: str) -> MatchResult:
        """Match ``message`` to a cluster, creating or generalising as needed."""
        tokens = tokenize(preprocess(message))
        leaf = self._descend(tokens, create=True)
        assert leaf is not None  # create=True always yields a node

        best: LogCluster | None = None
        best_score = -1.0
        for cluster in leaf.clusters:
            score = cluster.similarity(tokens)
            if score > best_score:
                best, best_score = cluster, score

        if best is not None and best_score >= self._threshold:
            updated = best.merge(tokens)
            return MatchResult(best.cluster_id, best.template, created=False, updated=updated)

        cluster = LogCluster(cluster_id=self._next_id, tokens=list(tokens), count=1)
        self._next_id += 1
        leaf.clusters.append(cluster)
        self._clusters[cluster.cluster_id] = cluster
        return MatchResult(cluster.cluster_id, cluster.template, created=True, updated=False)

    def match(self, message: str) -> MatchResult | None:
        """Match without mutating the tree.

        Used at inference time: the vocabulary must be frozen after training, or
        the model's token ids stop meaning what they meant when it was fitted.
        """
        tokens = tokenize(preprocess(message))
        leaf = self._descend(tokens, create=False)
        if leaf is None:
            return None

        best: LogCluster | None = None
        best_score = -1.0
        for cluster in leaf.clusters:
            score = cluster.similarity(tokens)
            if score > best_score:
                best, best_score = cluster, score

        if best is None or best_score < self._threshold:
            return None
        return MatchResult(best.cluster_id, best.template, created=False, updated=False)

    def fit(self, messages: Iterable[str]) -> DrainTemplateMiner:
        for message in messages:
            self.add(message)
        return self

    @property
    def clusters(self) -> list[LogCluster]:
        """Discovered templates, most frequent first."""
        return sorted(self._clusters.values(), key=lambda c: c.count, reverse=True)

    @property
    def vocabulary_size(self) -> int:
        return len(self._clusters)

    def to_dict(self) -> dict[str, object]:
        """Serialisable state.

        Only the cluster table is persisted; the tree is rebuilt from it. That
        keeps the on-disk form small and human-readable, and template ids stay
        stable across a restart — which matters because they are the model's
        token ids.
        """
        return {
            "depth": self._max_token_depth + 2,
            "similarity_threshold": self._threshold,
            "max_children": self._max_children,
            "next_id": self._next_id,
            "clusters": [
                {"cluster_id": c.cluster_id, "tokens": c.tokens, "count": c.count}
                for c in self._clusters.values()
            ],
        }

    @classmethod
    def from_dict(cls, state: dict) -> DrainTemplateMiner:
        miner = cls(
            depth=int(state["depth"]),
            similarity_threshold=float(state["similarity_threshold"]),
            max_children=int(state["max_children"]),
        )
        for raw in state["clusters"]:
            cluster = LogCluster(
                cluster_id=int(raw["cluster_id"]),
                tokens=list(raw["tokens"]),
                count=int(raw["count"]),
            )
            leaf = miner._descend(cluster.tokens, create=True)
            assert leaf is not None
            leaf.clusters.append(cluster)
            miner._clusters[cluster.cluster_id] = cluster
        miner._next_id = int(state["next_id"])
        return miner
